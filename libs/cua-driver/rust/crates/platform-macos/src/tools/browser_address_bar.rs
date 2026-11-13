// SPDX-License-Identifier: MIT
//! Native Chromium location editing without changing either app's key window.
//!
//! PID-routed keys still go to the process's key window. WindowKeyScope makes
//! them exact by taking key from a sibling, which ends the person's IME session.
//! This semantic route never posts keys, primes a window, or marks a document
//! edited. Ordinary input and its exact-window gates remain unchanged.

use super::ToolState;
use crate::ax::{bindings::*, snapshot::RetainedElement};
use core_foundation::{
    base::{CFRelease, CFTypeRef, TCFType},
    string::CFString,
};
use cua_driver_core::{
    action_record::{
        ActionEffect, ActionEvidence, ActionExecutionRecord, ActionTransport, ActualDelivery,
        EvidenceKind, RequestedDelivery,
    },
    protocol::ToolResult,
    tool::{Tool, ToolDef},
    tool_args::ArgsExt,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
struct Binding {
    pid: i32,
    window_id: u32,
    window: RetainedElement,
    field: RetainedElement,
    default_match: bool,
}
#[derive(Default)]
pub(crate) struct Routes(Mutex<HashMap<(String, String), Binding>>);
fn owner(args: &Value) -> (String, String) {
    (
        args.opt_str("_session_id").unwrap_or_default(),
        args.opt_str("session").unwrap_or_default(),
    )
}
impl Routes {
    pub(crate) fn clear(&self, args: &Value) {
        self.0.lock().unwrap().remove(&owner(args));
    }
    pub(crate) fn retire(&self, session: &str) {
        self.0
            .lock()
            .unwrap()
            .retain(|(transport, _), _| transport != session);
    }
    fn binding(&self, args: &Value, pid: i32, wid: u32) -> Option<Binding> {
        self.0
            .lock()
            .unwrap()
            .get(&owner(args))
            .filter(|b| b.pid == pid && b.window_id == wid)
            .cloned()
    }
    pub(crate) fn retain_field(&self, args: &Value, pid: i32, wid: u32, element: usize) {
        let same = self
            .binding(args, pid, wid)
            .is_some_and(|b| unsafe { equal(&b.field, &RetainedElement::retain(element)) });
        if !same {
            self.clear(args);
        }
    }
    fn set(&self, args: &Value, binding: Binding) {
        let mut routes = self.0.lock().unwrap();
        routes.insert(owner(args), binding);
    }
}

/// Clicks/menu operations establish a new input intention. Observation does not:
/// taking a snapshot between Cmd+L and typing must preserve the location target.
pub(crate) struct Reset<T> {
    inner: T,
    routes: Arc<Routes>,
}
impl<T> Reset<T> {
    pub(crate) fn new(inner: T, routes: Arc<Routes>) -> Self {
        Self { inner, routes }
    }
}
#[async_trait::async_trait]
impl<T: Tool> Tool for Reset<T> {
    fn def(&self) -> &ToolDef {
        self.inner.def()
    }
    // A lifecycle decorator must preserve implementation attestation. In
    // particular kill_app proves a process-instance fingerprint here; falling
    // back to Tool's defaults would discard that protected resource boundary.
    fn has_independent_input_lane(&self, args: &Value) -> bool {
        self.inner.has_independent_input_lane(args)
    }
    async fn protected_resource_ownership(
        &self,
        adapter: &str,
        args: &Value,
    ) -> cua_driver_core::tool::ProtectedResourceOwnership {
        self.inner.protected_resource_ownership(adapter, args).await
    }
    async fn protected_resource_scope(
        &self,
        adapter: &str,
        args: &Value,
    ) -> Result<Option<Value>, String> {
        self.inner.protected_resource_scope(adapter, args).await
    }
    async fn validate_protected_resource_scope(
        &self,
        adapter: &str,
        args: &Value,
        scope: &Value,
    ) -> Result<(), String> {
        self.inner
            .validate_protected_resource_scope(adapter, args, scope)
            .await
    }
    async fn invoke(&self, args: Value) -> ToolResult {
        self.routes.clear(&args);
        self.inner.invoke(args).await
    }
}

pub(crate) enum Operation {
    Hotkey { key: String, modifiers: Vec<String> },
    Text(String),
    Key { key: String, modifiers: Vec<String> },
}
#[derive(Clone)]
enum Action {
    Focus,
    Insert(String),
    Confirm,
}
fn action(operation: Operation) -> Option<Action> {
    match operation {
        Operation::Hotkey { key, modifiers }
            if key.eq_ignore_ascii_case("l")
                && !modifiers.is_empty()
                && modifiers.iter().all(|m| {
                    matches!(
                        m.to_ascii_lowercase().as_str(),
                        "cmd" | "command" | "meta" | "super" | "win"
                    )
                }) =>
        {
            Some(Action::Focus)
        }
        Operation::Text(text) if !text.chars().any(|c| matches!(c, '\n' | '\r' | '\t')) => {
            Some(Action::Insert(text))
        }
        Operation::Key { key, modifiers }
            if modifiers.is_empty()
                && matches!(
                    key.to_ascii_lowercase().as_str(),
                    "return" | "enter" | "kpenter" | "numpadenter"
                ) =>
        {
            Some(Action::Confirm)
        }
        _ => None,
    }
}
fn chromium(bundle: &str) -> bool {
    let bundle = bundle.to_ascii_lowercase();
    [
        "com.google.chrome",
        "org.chromium.chromium",
        "com.microsoft.edgemac",
        "com.brave.browser",
        "company.thebrowser.browser",
        "com.vivaldi.vivaldi",
        "com.operasoftware.opera",
    ]
    .iter()
    .any(|id| bundle == *id || bundle.starts_with(&format!("{id}.")))
}
pub(crate) unsafe fn is_address_bar(pid: i32, field: usize) -> bool {
    if !chromium(&crate::apps::bundle_id_for_pid(pid).unwrap_or_default()) {
        return false;
    }
    let Some(window) = copy_element_attr(field as AXUIElementRef, "AXWindow").map(|w| retained(w))
    else {
        return false;
    };
    let Some(wid) = ax_get_window_id(ptr(&window)) else {
        return false;
    };
    locate(pid, wid).is_some_and(|b| equal(&b.field, &RetainedElement::retain(field)))
}
fn execution_record(action: &Action) -> ActionExecutionRecord {
    let confirm = matches!(action, Action::Confirm);
    let mut result=ActionExecutionRecord::builder(if confirm{ActionEffect::Unverifiable}else{ActionEffect::Confirmed},
        if confirm{ActionTransport::MacosAxAction}else{ActionTransport::MacosAxValue},RequestedDelivery::Background)
        .actual_delivery(ActualDelivery::Background).evidence(ActionEvidence{
            kind:if confirm{EvidenceKind::NativeApiResult}else{EvidenceKind::AccessibilityReadback},
            detail:if confirm{"the associated native address suggestion accepted AXPress; navigation needs observation"}
                else{"the exact native address control's text selection or inserted value was read back"}.into(),
        }).build().expect("native address execution evidence is valid");
    if let Action::Insert(text) = action {
        result.delivered_count = text.chars().count().try_into().ok();
    }
    result
}
fn response(action: Action, data: Value) -> ToolResult {
    let record = execution_record(&action);
    ToolResult::text(match action {Action::Focus=>"Selected the native browser address bar as this session's text target through accessibility.",Action::Insert(_)=>"Inserted text into the native browser address bar through accessibility.",Action::Confirm=>"Sent address confirmation through the associated native suggestion; observe the target window to verify navigation."})
        .with_structured(data).with_action_record(record)
}
fn failure(message: impl Into<String>) -> ToolResult {
    ToolResult::error(message.into()).with_structured(json!({"code":"address_bar_operation_failed", "route":"accessibility", "effect":"unverifiable"}))
}
unsafe fn retained(owned: AXUIElementRef) -> RetainedElement {
    let result = RetainedElement::retain(owned as usize);
    CFRelease(owned as CFTypeRef);
    result
}
fn ptr(e: &RetainedElement) -> AXUIElementRef {
    e.as_ptr() as AXUIElementRef
}
fn equal(a: &RetainedElement, b: &RetainedElement) -> bool {
    extern "C" {
        fn CFEqual(a: CFTypeRef, b: CFTypeRef) -> u8;
    }
    unsafe { CFEqual(ptr(a) as CFTypeRef, ptr(b) as CFTypeRef) != 0 }
}
fn omnibox_ui_url(url: &str) -> bool {
    [
        "chrome://omnibox-popup.top-chrome/",
        "chrome://omnibox-popup/",
        "edge://omnibox-popup.top-chrome/",
        "edge://omnibox-popup/",
    ]
    .iter()
    .any(|prefix| url.starts_with(prefix))
}
fn excluded(role: &str) -> bool {
    matches!(role, "AXWebArea" | "AXSheet" | "AXDialog") || role.contains("Menu")
}
struct Node {
    element: RetainedElement,
    role: String,
    depth: usize,
    in_list: bool,
}
unsafe fn walk(root: &RetainedElement) -> Vec<Node> {
    let mut out = Vec::new();
    let mut stack = vec![(root.clone(), 0, false)];
    while let Some((element, depth, in_list)) = stack.pop() {
        if depth > 16 || out.len() >= 512 {
            continue;
        }
        let role = copy_string_attr(ptr(&element), "AXRole").unwrap_or_default();
        if role == "AXWebArea" {
            // Current Chromium renders its native suggestion popup in privileged
            // WebUI. Never admit ordinary page content, including lookalike labels.
            let url = copy_url_attr(ptr(&element)).unwrap_or_default();
            if !omnibox_ui_url(&url)
                || ax_get_window_id(ptr(&element)) == ax_get_window_id(ptr(root))
            {
                continue;
            }
        } else if excluded(&role) {
            continue;
        }
        let in_list = in_list || role == "AXList";
        let children = copy_children(ptr(&element));
        for child in children.into_iter().rev() {
            stack.push((retained(child), depth + 1, in_list));
        }
        out.push(Node {
            element,
            role,
            depth,
            in_list,
        });
    }
    out
}
unsafe fn windows(pid: i32) -> Vec<RetainedElement> {
    let app = retained(AXUIElementCreateApplication(pid));
    copy_ax_windows(ptr(&app))
        .into_iter()
        .map(|w| retained(w))
        .collect()
}
unsafe fn locate(pid: i32, wid: u32) -> Option<Binding> {
    let window = windows(pid)
        .into_iter()
        .find(|w| ax_get_window_id(ptr(w)) == Some(wid))?;
    let mut fields: Vec<_> = walk(&window)
        .into_iter()
        .filter(|n| {
            n.role == "AXTextField"
                && !n.in_list
                && ax_get_window_id(ptr(&n.element)) == Some(wid)
                && copy_string_attr(ptr(&n.element), "AXValue").is_some()
                && range(&n.element).is_some()
        })
        .collect();
    fields.sort_by_key(|n| n.depth);
    let first = fields.first()?;
    // The top native field is the omnibox. An ambiguous peer is not silently
    // chosen: page inputs, find panels and suggestion text cannot authorize it.
    if fields.get(1).is_some_and(|n| n.depth == first.depth) {
        return None;
    }
    Some(Binding {
        pid,
        window_id: wid,
        window,
        field: first.element.clone(),
        default_match: false,
    })
}
#[repr(C)]
struct RawRange {
    location: isize,
    length: isize,
}
#[derive(Clone, Copy, Debug, PartialEq)]
struct Range {
    location: usize,
    length: usize,
}
unsafe fn range(element: &RetainedElement) -> Option<Range> {
    let name = CFString::new("AXSelectedTextRange");
    let mut value: CFTypeRef = std::ptr::null();
    if AXUIElementCopyAttributeValue(ptr(element), name.as_concrete_TypeRef(), &mut value) != 0
        || value.is_null()
    {
        return None;
    }
    extern "C" {
        fn AXValueGetTypeID() -> core_foundation::base::CFTypeID;
    }
    if core_foundation::base::CFGetTypeID(value) != AXValueGetTypeID() {
        CFRelease(value);
        return None;
    }
    let mut raw = RawRange {
        location: -1,
        length: -1,
    };
    let ok = AXValueGetValue(
        value as AXValueRef,
        kAXValueCFRangeType,
        &mut raw as *mut _ as *mut _,
    );
    CFRelease(value);
    (ok && raw.location >= 0 && raw.length >= 0).then_some(Range {
        location: raw.location as usize,
        length: raw.length as usize,
    })
}
unsafe fn select_text(element: &RetainedElement, wanted: Range) -> bool {
    // Match upstream #5976's UTF-16 {location,length} and write/read-back shape;
    // this does not introduce a competing public selection-tool protocol.
    let raw = RawRange {
        location: wanted.location as isize,
        length: wanted.length as isize,
    };
    let value = AXValueCreate(kAXValueCFRangeType, &raw as *const _ as *const _);
    if value.is_null() {
        return false;
    }
    let name = CFString::new("AXSelectedTextRange");
    let result =
        AXUIElementSetAttributeValue(ptr(element), name.as_concrete_TypeRef(), value as CFTypeRef);
    CFRelease(value as CFTypeRef);
    result == 0 && range(element) == Some(wanted)
}
fn inserted(before: &str, selected: Range, text: &str) -> Option<(String, usize)> {
    let mut value: Vec<_> = before.encode_utf16().collect();
    let end = selected.location.checked_add(selected.length)?;
    if end > value.len() {
        return None;
    }
    let insert: Vec<_> = text.encode_utf16().collect();
    let caret = selected.location + insert.len();
    value.splice(selected.location..end, insert);
    Some((String::from_utf16(&value).ok()?, caret))
}
unsafe fn popup_row(binding: &Binding) -> Result<RetainedElement, String> {
    // A suggestion's AXWindow is a separate popup, so the ordinary click gate
    // correctly rejects it. Prove the *logical* association afresh instead:
    // selected native-list row reachable only from this exact main window,
    // plus fresh WindowServer ownership of its physical popup. No generic
    // element/window check is weakened.
    let deadline = Instant::now() + Duration::from_secs(2);
    let rows = loop {
        let rows: Vec<_> = walk(&binding.window)
            .into_iter()
            .filter(|n| {
                n.in_list
                    && n.role == "AXStaticText"
                    && copy_action_names(ptr(&n.element))
                        .iter()
                        .any(|a| a == "AXPress")
            })
            .collect();
        if !rows.is_empty() {
            break rows;
        }
        if Instant::now() >= deadline {
            return Err("The native address suggestion did not become available; read the target window again.".into());
        }
        // Only observation is retried. AXPress happens exactly once after proof.
        std::thread::sleep(Duration::from_millis(40));
    };
    let selected: Vec<_> = rows
        .iter()
        .filter(|n| copy_bool_attr(ptr(&n.element), "AXSelected") == Some(true))
        .collect();
    let row = if selected.len() == 1 {
        selected[0].element.clone()
    } else if selected.is_empty() && binding.default_match {
        // A fresh text insertion resets Chrome's default match to the first row.
        // WebUI exposes neither AXSelected nor AXSelectedChildren for that match.
        rows.first().ok_or("The target address bar has no associated native suggestion; read that window again.")?.element.clone()
    } else {
        return Err("The address bar has no uniquely proven selected suggestion.".into());
    };
    let popup = copy_element_attr(ptr(&row), "AXWindow")
        .map(|w| retained(w))
        .ok_or("The suggestion has no native window.")?;
    let popup_id =
        ax_get_window_id(ptr(&popup)).ok_or("The suggestion popup has no window identity.")?;
    if !crate::windows::all_windows()
        .iter()
        .any(|w| w.window_id == popup_id && w.pid == binding.pid)
    {
        return Err("The suggestion popup's process ownership changed.".into());
    }
    for other in windows(binding.pid) {
        let id = ax_get_window_id(ptr(&other));
        if id == Some(binding.window_id) || id == Some(popup_id) {
            continue;
        }
        if walk(&other).iter().any(|n| equal(&n.element, &row)) {
            return Err(
                "The address suggestion is also associated with another browser window.".into(),
            );
        }
    }
    Ok(row)
}
unsafe fn perform(binding: &Binding, action: &Action) -> Result<Value, String> {
    let field = ptr(&binding.field);
    match action {
        Action::Focus => {
            // AXFocused and AXPress activate a sibling in current Chromium.
            // Selection establishes the agent's text target without making it key.
            let text = copy_string_attr(field, "AXValue")
                .ok_or("The address bar's text could not be read.")?;
            let selected = Range {
                location: 0,
                length: text.encode_utf16().count(),
            };
            if !select_text(&binding.field, selected) {
                return Err(
                    "The address bar's selection did not match the requested UTF-16 range.".into(),
                );
            }
            Ok(
                json!({"effect":"confirmed", "selection_type":"text", "text":text, "range":{"location":0,"length":selected.length}}),
            )
        }
        Action::Insert(text) => {
            let before = copy_string_attr(field, "AXValue")
                .ok_or("The address bar's text could not be read.")?;
            let selected =
                range(&binding.field).ok_or("The address bar has no readable selection.")?;
            let (expected, caret) = inserted(&before, selected, text)
                .ok_or("The native address selection is outside its text.")?;
            // Browser chrome is not an NSDocument. An AX write updates Chrome's
            // edit model; the generic net-zero edit would steal a sibling's key.
            // AXValue calls OmniboxView::SetUserText(update_popup=true), while
            // AXSelectedText can update the displayed text without its suggestions.
            if set_string_attr(field, "AXValue", &expected) != 0 {
                return Err("The native address bar did not accept the text.".into());
            }
            if copy_string_attr(field, "AXValue").as_deref() != Some(expected.as_str()) {
                return Err("The address bar's value did not match the insertion; no retry or keys were sent.".into());
            }
            if !select_text(
                &binding.field,
                Range {
                    location: caret,
                    length: 0,
                },
            ) {
                return Err(
                    "The address bar's caret could not be verified after insertion.".into(),
                );
            }
            Ok(
                json!({"effect":"confirmed", "delivered_count":text.chars().count(), "document_key_edit_sent":false}),
            )
        }
        Action::Confirm => {
            let row = popup_row(binding)?;
            if perform_action(ptr(&row), "AXPress") != 0 {
                return Err(
                    "The address suggestion did not accept its accessibility action.".into(),
                );
            }
            Ok(
                json!({"effect":"unverifiable", "confirmation":"associated_address_suggestion", "evidence":[{"kind":"accessibility_action","detail":"pressed the unique selected suggestion associated with this exact native address bar; observe the target page to verify navigation"}]}),
            )
        }
    }
}

pub(crate) async fn route(
    state: Arc<ToolState>,
    args: &Value,
    pid: i32,
    wid: Option<u32>,
    explicit: Option<usize>,
    foreground: bool,
    pixels: bool,
    operation: Operation,
) -> Option<ToolResult> {
    let action = action(operation);
    if foreground || pixels || wid.is_none() || action.is_none() {
        state.address_bar_routes.clear(args);
        return None;
    }
    let wid = wid.unwrap();
    let action = action.unwrap();
    let old = state.address_bar_routes.binding(args, pid, wid);
    let focus = matches!(action, Action::Focus);
    let observed = tokio::task::spawn_blocking(move || unsafe {
        if !chromium(&crate::apps::bundle_id_for_pid(pid).unwrap_or_default()) {
            return (false, None);
        }
        (true, locate(pid, wid))
    })
    .await;
    let mut target = match observed {
        Ok((false, _)) => {
            state.address_bar_routes.clear(args);
            return None;
        }
        Ok((true, Some(target))) => target,
        _ => {
            state.address_bar_routes.clear(args);
            return focus.then(|| {
                failure("The Chromium address bar could not be identified in the requested window.")
            });
        }
    };
    if !focus {
        let current = old
            .as_ref()
            .is_some_and(|b| equal(&b.window, &target.window) && equal(&b.field, &target.field));
        let exact =
            explicit.is_some_and(|p| unsafe { equal(&RetainedElement::retain(p), &target.field) });
        if !current && !exact {
            state.address_bar_routes.clear(args);
            return None;
        }
        if current {
            target.default_match = old.as_ref().unwrap().default_match;
        }
    }
    if explicit.is_some_and(|p| unsafe { !equal(&RetainedElement::retain(p), &target.field) })
        && !focus
    {
        state.address_bar_routes.clear(args);
        return None;
    }
    let _lease = match super::gate_background_window_action(
        pid,
        wid,
        Some(target.field.as_ptr()),
        cua_driver_core::background_input::BackgroundAction::AxSemantic,
    )
    .await
    {
        Ok(lease) => lease,
        Err(error) => return Some(error),
    };
    let target_copy = target.clone();
    let action_copy = action.clone();
    let result = tokio::task::spawn_blocking(move || unsafe {
        let mut fresh = locate(pid, wid)
            .ok_or("The browser window changed before the accessibility action.".to_string())?;
        if !equal(&fresh.window, &target_copy.window) || !equal(&fresh.field, &target_copy.field) {
            return Err("The native address control changed before execution.".into());
        }
        fresh.default_match = target_copy.default_match;
        perform(&fresh, &action_copy)
    })
    .await;
    match result {
        Ok(Ok(mut data)) => {
            if matches!(action, Action::Confirm) {
                state.address_bar_routes.clear(args);
            } else {
                target.default_match = matches!(action, Action::Insert(_));
                state.address_bar_routes.set(args, target);
            }
            super::cursor_tools::position_keyboard_cursor(&state, args, Some(wid), None).await;
            data["path"] = json!("ax");
            data["verified"] = json!(!matches!(action, Action::Confirm));
            data["route"] = json!("accessibility");
            data["delivery"] = json!({"mode":"background"});
            data["pid"] = json!(pid);
            data["window_id"] = json!(wid);
            Some(response(action, data))
        }
        Ok(Err(error)) => {
            state.address_bar_routes.clear(args);
            Some(failure(error))
        }
        Err(error) => {
            state.address_bar_routes.clear(args);
            Some(failure(format!(
                "Address-bar accessibility action failed: {error}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_uses_utf16_and_preserves_unselected_text() {
        assert_eq!(
            inserted(
                "A😀BC",
                Range {
                    location: 1,
                    length: 2
                },
                "你好"
            ),
            Some(("A你好BC".into(), 3))
        );
        assert_eq!(
            inserted(
                "ab",
                Range {
                    location: 1,
                    length: 0
                },
                "c"
            ),
            Some(("acb".into(), 2))
        );
        assert!(inserted(
            "😀",
            Range {
                location: 1,
                length: 0
            },
            "x"
        )
        .is_none());
        assert!(inserted(
            "a",
            Range {
                location: 1,
                length: usize::MAX
            },
            "x"
        )
        .is_none());
    }
    #[test]
    fn only_location_shortcuts_have_semantic_focus_intent() {
        for name in ["cmd", "command", "meta", "super", "win", "CMD"] {
            assert!(matches!(
                action(Operation::Hotkey {
                    key: "L".into(),
                    modifiers: vec![name.into()]
                }),
                Some(Action::Focus)
            ));
        }
        for mods in [
            vec![],
            vec!["ctrl".into()],
            vec!["cmd".into(), "shift".into()],
        ] {
            assert!(action(Operation::Hotkey {
                key: "l".into(),
                modifiers: mods
            })
            .is_none());
        }
        assert!(action(Operation::Key {
            key: "Return".into(),
            modifiers: vec!["cmd".into()]
        })
        .is_none());
    }
    #[test]
    fn browser_identity_and_tree_boundaries_are_native_and_narrow() {
        assert!(chromium("com.google.Chrome"));
        assert!(chromium("com.google.Chrome.forTesting"));
        assert!(chromium("com.microsoft.edgemac"));
        assert!(!chromium("com.apple.dt.Xcode"));
        assert!(!chromium("com.google.chromeevil"));
        for role in ["AXWebArea", "AXMenu", "AXMenuItem", "AXDialog", "AXSheet"] {
            assert!(excluded(role));
        }
        assert!(!excluded("AXToolbar"));
    }
    #[test]
    fn intention_keys_isolate_transport_and_explicit_lane() {
        assert_ne!(
            owner(&json!({"_session_id":"one","session":"shared"})),
            owner(&json!({"_session_id":"two","session":"shared"}))
        );
        assert_ne!(
            owner(&json!({"_session_id":"one","session":"a"})),
            owner(&json!({"_session_id":"one","session":"b"}))
        );
    }
    fn stub_binding(pid: i32, window_id: u32) -> Binding {
        Binding {
            pid,
            window_id,
            window: unsafe { RetainedElement::retain(0) },
            field: unsafe { RetainedElement::retain(0) },
            default_match: false,
        }
    }
    #[test]
    fn input_intention_is_window_and_connection_owned_until_explicit_reset() {
        let routes = Routes::default();
        let a = json!({"_session_id":"transport-a","session":"lane"});
        let b = json!({"_session_id":"transport-b","session":"lane"});
        routes.set(&a, stub_binding(42, 7));
        routes.set(&b, stub_binding(42, 8));
        assert!(routes.binding(&a, 42, 7).is_some());
        assert!(routes.binding(&a, 42, 8).is_none());
        assert!(routes.binding(&a, 43, 7).is_none());
        routes.retire("transport-a");
        assert!(routes.binding(&a, 42, 7).is_none());
        assert!(routes.binding(&b, 42, 8).is_some());
        routes.clear(&b);
        assert!(routes.binding(&b, 42, 8).is_none());
    }
    #[test]
    fn privileged_popup_urls_cannot_be_spoofed_by_web_content() {
        for url in [
            "chrome://omnibox-popup.top-chrome/",
            "chrome://omnibox-popup/",
            "edge://omnibox-popup/",
        ] {
            assert!(omnibox_ui_url(url));
        }
        for url in [
            "https://omnibox-popup.top-chrome/",
            "chrome://omnibox-popup.top-chrome.evil/",
            "chrome://settings/",
            "file:///omnibox-popup",
        ] {
            assert!(!omnibox_ui_url(url));
        }
    }
    struct WireFixture;
    #[async_trait::async_trait]
    impl Tool for WireFixture {
        fn def(&self) -> &ToolDef {
            static DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();
            DEF.get_or_init(||ToolDef{name:"hotkey".into(),description:"semantic result contract fixture".into(),input_schema:json!({"type":"object","properties":{"pid":{"type":"integer"},"window_id":{"type":"integer"},"keys":{"type":"array","items":{"type":"string"}}}}),read_only:false,destructive:true,idempotent:false,open_world:true})
        }
        async fn invoke(&self, _args: Value) -> ToolResult {
            response(Action::Focus, json!({"effect":"confirmed"}))
        }
    }
    #[tokio::test]
    async fn semantic_success_survives_the_real_action_outcome_boundary() {
        let mut registry = cua_driver_core::tool::ToolRegistry::new();
        registry.register(Box::new(WireFixture));
        let result = registry
            .invoke(
                "hotkey",
                json!({"target":{"kind":"window","pid":42,"window_id":7},"keys":["cmd","l"]}),
            )
            .await;
        assert_ne!(result.is_error, Some(true), "{:?}", result.content);
        let data = result.structured_content.unwrap();
        assert_eq!(data["route"], "accessibility");
        assert_eq!(data["effect"], "confirmed");
        assert!(execution_record(&Action::Confirm).public_result().is_ok());
    }
    struct DelegationFixture;
    #[async_trait::async_trait]
    impl Tool for DelegationFixture {
        fn def(&self) -> &ToolDef {
            static INNER: WireFixture = WireFixture;
            INNER.def()
        }
        fn has_independent_input_lane(&self, _args: &Value) -> bool {
            true
        }
        async fn protected_resource_ownership(
            &self,
            _adapter: &str,
            _args: &Value,
        ) -> cua_driver_core::tool::ProtectedResourceOwnership {
            cua_driver_core::tool::ProtectedResourceOwnership::DriverOwned
        }
        async fn protected_resource_scope(
            &self,
            _adapter: &str,
            args: &Value,
        ) -> Result<Option<Value>, String> {
            Ok(Some(json!({"pid":args["pid"],"native_identity":"fixture"})))
        }
        async fn validate_protected_resource_scope(
            &self,
            _adapter: &str,
            _args: &Value,
            _scope: &Value,
        ) -> Result<(), String> {
            Err("inner-validation-marker".into())
        }
        async fn invoke(&self, _args: Value) -> ToolResult {
            ToolResult::text("delegated")
        }
    }
    #[tokio::test]
    async fn reset_preserves_implementation_attested_input_and_resource_contracts() {
        let args = json!({"pid":42});
        let wrapped = Reset::new(DelegationFixture, Arc::new(Routes::default()));
        assert!(wrapped.has_independent_input_lane(&args));
        assert_eq!(
            wrapped
                .protected_resource_ownership("process_control", &args)
                .await,
            cua_driver_core::tool::ProtectedResourceOwnership::DriverOwned
        );
        assert_eq!(
            wrapped
                .protected_resource_scope("process_control", &args)
                .await
                .unwrap(),
            Some(json!({"pid":42,"native_identity":"fixture"}))
        );
        assert_eq!(
            wrapped
                .validate_protected_resource_scope("process_control", &args, &json!({}))
                .await,
            Err("inner-validation-marker".into())
        );
        // The real kill tool must still reject an invalid process identity at
        // the attestation boundary, before any termination can be dispatched.
        let kill = Reset::new(
            super::super::kill_app::KillAppTool,
            Arc::new(Routes::default()),
        );
        assert_eq!(
            kill.protected_resource_scope("process_control", &json!({"pid":-1}))
                .await,
            Err("kill_app requires a positive integer pid".into())
        );
    }
}
