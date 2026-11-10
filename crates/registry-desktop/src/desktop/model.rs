use chrono::{Local, TimeZone};
use registry_core::{changes::is_repair_candidate, Category, EntryStatus, RegistryEntry};
use std::collections::{HashMap, HashSet};

pub const CATEGORIES: &[(Category, &str)] = &[
    (Category::Startup, "Startup"),
    (Category::AppPaths, "Application paths"),
    (Category::ApplicationLeftovers, "Application leftovers"),
    (Category::Uninstall, "Installed programs"),
    (Category::ApplicationCommands, "Application commands"),
    (Category::ApplicationIcons, "Application icons"),
    (Category::RegisteredApplications, "Registered applications"),
    (Category::FileAssociations, "File associations"),
    (Category::ShellMenus, "Context menus"),
    (Category::Services, "Windows services"),
    (Category::SharedDlls, "Shared DLLs"),
    (Category::Com, "COM servers"),
    (Category::TypeLibraries, "Type libraries"),
    (Category::ProgIds, "ProgIDs"),
    (Category::Interfaces, "COM interfaces"),
    (Category::ComProxies, "COM proxies"),
    (Category::ComRedirections, "COM redirections"),
    (Category::ComConversions, "COM conversions"),
    (Category::Fonts, "Fonts"),
    (Category::HelpFiles, "Help files"),
    (Category::SoundEvents, "Sound events"),
    (Category::MuiCache, "Display cache"),
    (Category::UsageHistory, "Usage history"),
];

pub fn category_name(category: Category) -> &'static str {
    CATEGORIES
        .iter()
        .find(|(candidate, _)| *candidate == category)
        .expect("every registry category has a label")
        .1
}

pub fn status_name(status: EntryStatus) -> &'static str {
    match status {
        EntryStatus::Found => "Found",
        EntryStatus::Review => "Review",
        EntryStatus::Unknown => "Unverified",
    }
}

pub fn view_name(view: &str) -> String {
    match view {
        "32" => "32-bit",
        "64" => "64-bit",
        "shared" => "Shared",
        other => other,
    }
    .to_string()
}

pub fn location(entry: &RegistryEntry) -> String {
    format!("{}\\{}", entry.hive, entry.key_path)
}

pub fn count(value: usize) -> String {
    let digits = value.to_string();
    let mut result = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            result.push(',');
        }
        result.push(digit);
    }
    result
}

pub fn timestamp(value: u64) -> String {
    i64::try_from(value)
        .ok()
        .and_then(|ms| Local.timestamp_millis_opt(ms).single())
        .map_or_else(
            || "Unknown date".into(),
            |date| date.format("%b %-d, %Y · %H:%M").to_string(),
        )
}

pub fn duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.1} s", ms as f64 / 1000.0)
    }
}

pub fn pretty(value: &str) -> String {
    value.replace(['_', '-'], " ")
}

pub struct LeftoverGroup {
    pub anchor: usize,
    pub related: Vec<usize>,
}

pub fn leftover_groups(entries: &[RegistryEntry]) -> Vec<LeftoverGroup> {
    let by_id: HashMap<_, _> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.id.as_str(), index))
        .collect();
    let mut by_evidence = HashMap::new();
    let mut groups: Vec<LeftoverGroup> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some(evidence) = entry.leftover_evidence.as_ref().filter(|_| {
            entry.category == Category::ApplicationLeftovers
                && entry.assessment.status == EntryStatus::Review
        }) else {
            continue;
        };
        let key = [
            evidence.executable.to_lowercase(),
            evidence.directory.to_lowercase(),
            evidence.uninstall_path.to_lowercase(),
        ];
        let slot = *by_evidence.entry(key).or_insert_with(|| {
            let slot = groups.len();
            groups.push(LeftoverGroup {
                anchor: index,
                related: Vec::new(),
            });
            slot
        });
        let group = &mut groups[slot];
        if !entries[group.anchor].leftover_repairable && entry.leftover_repairable {
            group.anchor = index;
        }
        group.related.push(index);
        group.related.extend(
            evidence
                .related_ids
                .iter()
                .filter_map(|id| by_id.get(id.as_str()).copied()),
        );
    }
    for group in &mut groups {
        let mut seen = HashSet::new();
        group.related.retain(|index| seen.insert(*index));
    }
    groups
}

#[derive(Default)]
pub struct Filter {
    pub query: String,
    pub category: Option<Category>,
    pub status: Option<EntryStatus>,
}

impl Filter {
    pub fn indices(&self, entries: &[RegistryEntry], candidates_only: bool) -> Vec<usize> {
        let query = self.query.trim().to_lowercase();
        entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                if self
                    .category
                    .is_some_and(|category| category != entry.category)
                    || self
                        .status
                        .is_some_and(|status| status != entry.assessment.status)
                    || (candidates_only && !is_repair_candidate(entry))
                {
                    return None;
                }
                let matches = query.is_empty()
                    || [
                        entry.name.as_str(),
                        entry.value_name.as_str(),
                        entry.raw_value.as_str(),
                        entry.key_path.as_str(),
                        entry.hive.as_str(),
                        entry.assessment.target.as_deref().unwrap_or_default(),
                        entry.publisher.as_deref().unwrap_or_default(),
                        category_name(entry.category),
                    ]
                    .iter()
                    .any(|field| field.to_lowercase().contains(&query));
                matches.then_some(index)
            })
            .collect()
    }
}
