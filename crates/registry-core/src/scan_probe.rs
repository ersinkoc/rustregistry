use crate::{PathProbe, ProbeResult, TargetKind};
use std::{cell::RefCell, collections::HashSet};

/// Reuse positive observations of the exact same target during one read-only scan.
/// Missing/uncertain targets and all change-manager verification remain uncached.
pub(crate) struct ScanProbe<P> {
    inner: P,
    found: RefCell<HashSet<(String, bool)>>,
}
impl<P> ScanProbe<P> {
    pub(crate) fn new(inner: P) -> Self {
        Self {
            inner,
            found: RefCell::new(HashSet::new()),
        }
    }
}
impl<P: PathProbe> PathProbe for ScanProbe<P> {
    fn probe(&self, path: &str, kind: TargetKind) -> ProbeResult {
        // Preserve case: Windows directories can explicitly enable case sensitivity.
        let key = (path.to_owned(), matches!(kind, TargetKind::Directory));
        if self.found.borrow().contains(&key) {
            return ProbeResult::Found;
        }
        let result = self.inner.probe(path, kind);
        if result == ProbeResult::Found {
            self.found.borrow_mut().insert(key);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze_target, EntryStatus, Environment};
    use std::{cell::Cell, rc::Rc};
    struct Probe {
        calls: Rc<Cell<usize>>,
        result: Rc<Cell<ProbeResult>>,
    }
    impl PathProbe for Probe {
        fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
            self.calls.set(self.calls.get() + 1);
            self.result.get()
        }
    }
    #[test]
    fn duplicate_positive_scan_targets_do_not_repeat_filesystem_queries() {
        let calls = Rc::new(Cell::new(0));
        let result = Rc::new(Cell::new(ProbeResult::Found));
        let probe = ScanProbe::new(Probe {
            calls: calls.clone(),
            result,
        });
        for _ in 0..100 {
            assert_eq!(
                analyze_target(
                    r"C:\Apps\app.exe",
                    TargetKind::File,
                    &Environment::default(),
                    &probe
                )
                .status,
                EntryStatus::Found
            );
        }
        assert_eq!(calls.get(), 1);
        analyze_target(
            r"C:\Apps\app.exe",
            TargetKind::Directory,
            &Environment::default(),
            &probe,
        );
        assert_eq!(calls.get(), 2);
        analyze_target(
            r"C:\Apps\App.exe",
            TargetKind::File,
            &Environment::default(),
            &probe,
        );
        assert_eq!(calls.get(), 3);
    }
    #[test]
    fn missing_uncertain_and_new_scan_observations_are_always_checked_again() {
        for first in [
            ProbeResult::Missing,
            ProbeResult::Inaccessible,
            ProbeResult::Redirected,
            ProbeResult::WrongKind,
        ] {
            let calls = Rc::new(Cell::new(0));
            let result = Rc::new(Cell::new(first));
            let probe = ScanProbe::new(Probe {
                calls: calls.clone(),
                result: result.clone(),
            });
            assert_ne!(
                probe.probe(r"C:\Apps\app.exe", TargetKind::File),
                ProbeResult::Found
            );
            result.set(ProbeResult::Found);
            assert_eq!(
                probe.probe(r"C:\Apps\app.exe", TargetKind::File),
                ProbeResult::Found
            );
            assert_eq!(calls.get(), 2);
            result.set(ProbeResult::Missing);
            let next = ScanProbe::new(Probe {
                calls: calls.clone(),
                result: result.clone(),
            });
            assert_eq!(
                next.probe(r"C:\Apps\app.exe", TargetKind::File),
                ProbeResult::Missing
            );
        }
    }
}
