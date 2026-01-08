use anyhow::{
    Context,
    Result,
};
use clap::Parser;
use serde::Serialize;
use sexp::{
    Atom,
    Sexp,
};
use std::collections::{
    HashMap,
    HashSet,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "dune-graph")]
#[command(about = "Analyze build targets and dependencies from dune files")]
struct Args {
    #[arg(long, default_value = "text", help = "For now only text is supported")]
    format: String,
    #[arg(long, default_value = ".", help = "Expected to be a repo root, with a src directory")]
    root: PathBuf,
    #[arg(long, help = "Maximum depth level to resolve dependencies - set to 0 to list all build targets (no dependency graph)")]
    level: Option<usize>,
    #[arg(long, help = "Focus on a specific target (e.g., --target foobar)")]
    target: Option<String>,
    #[arg(long, short, action, help = "Use pattern matching for --target (matches substring like foo)")]
    pattern: bool,
    #[arg(long, short, action, help = "Include fully resolved dependency graph")]
    full_graph: bool,
    #[arg(long, short, action, help = "Show list of all unique dependencies.")]
    unique_list: bool,
}

#[derive(Debug, Clone, Serialize)]
struct TargetInfo {
    name: String,
    path: String,
    package: String,
    public_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DependencyNode {
    name: String,
    #[serde(rename = "type")]
    node_type: String,
    path: String,
    dependencies: Vec<DependencyNode>,
}

#[derive(Debug, Clone, Serialize)]
struct AnalysisResult {
    targets: Vec<TargetInfo>,
    dependency_graphs: HashMap<String, DependencyNode>,
    all_unique_dependencies: Vec<String>,
    external_dependencies: Vec<String>,
}

struct DependencyAnalyzer {
    root_dir: PathBuf,
    src_dir: PathBuf,
    dependency_cache: HashMap<String, HashSet<String>>,
    visited_libs: HashSet<String>,
    expanded_libs: HashSet<String>, // Track which libraries have been fully expanded in output
    all_dependencies: HashSet<String>, // Collect all unique dependencies
    external_dependencies: HashSet<String>, // Collect all external/opam/missing dependencies
    library_index: HashMap<String, PathBuf>, // Map of library name -> dune file path
    executable_targets: Vec<TargetInfo>, // All executable targets found during walk
}

impl DependencyAnalyzer {
    fn new(root_dir: PathBuf) -> Self {
        let src_dir = root_dir.join("src");
        Self {
            root_dir,
            src_dir,
            dependency_cache: HashMap::new(),
            visited_libs: HashSet::new(),
            expanded_libs: HashSet::new(),
            all_dependencies: HashSet::new(),
            external_dependencies: HashSet::new(),
            library_index: HashMap::new(),
            executable_targets: Vec::new(),
        }
    }

    fn build_library_index(&mut self) -> Result<()> {
        eprintln!("Building library index from src/ tree...");
        let src_dir = self.src_dir.clone();
        self.walk_and_index_dune_files(&src_dir)?;
        
        // Also check root dune and dune-project files
        let root_dune = self.root_dir.join("dune");
        if root_dune.exists() {
            if let Ok(sexps) = self.parse_dune_file(&root_dune) {
                for sexp in &sexps {
                    self.index_library_from_sexp(sexp, &root_dune);
                    self.extract_executables_from_sexp(sexp, &root_dune);
                }
            }
        }
        
        let root_dune_project = self.root_dir.join("dune-project");
        if root_dune_project.exists() {
            if let Ok(sexps) = self.parse_dune_file(&root_dune_project) {
                for sexp in &sexps {
                    self.index_library_from_sexp(sexp, &root_dune_project);
                    self.extract_executables_from_sexp(sexp, &root_dune_project);
                }
            }
        }
        
        eprintln!("Indexed {} libraries", self.library_index.len());
        eprintln!("Found {} executable targets", self.executable_targets.len());
        Ok(())
    }

    fn walk_and_index_dune_files(&mut self, dir: &PathBuf) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        // Check for dune files
        let dune_file = dir.join("dune");
        if dune_file.exists() {
            if let Ok(sexps) = self.parse_dune_file(&dune_file) {
                for sexp in &sexps {
                    self.index_library_from_sexp(sexp, &dune_file);
                    self.extract_executables_from_sexp(sexp, &dune_file);
                }
            }
        }

        // walk subdirectories
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Skip .git and other hidden directories
                    if let Some(name) = path.file_name() {
                        let name_str = name.to_string_lossy();
                        if name_str.starts_with('.') {
                            continue;
                        }
                    }
                    self.walk_and_index_dune_files(&path)?;
                }
            }
        }

        Ok(())
    }

    fn index_library_from_sexp(&mut self, sexp: &Sexp, dune_file: &PathBuf) {
        if let Sexp::List(list) = sexp {
            if let Some(Sexp::Atom(Atom::S(s))) = list.first() {
                if s == "library" {
                    // Extract names
                    let mut name: Option<String> = None;
                    let mut public_name: Option<String> = None;

                    for item in list.iter().skip(1) {
                        if let Sexp::List(inner) = item {
                            if let Some(Sexp::Atom(Atom::S(key))) = inner.first() {
                                if key == "name" && inner.len() >= 2 {
                                    if let Some(Sexp::Atom(Atom::S(n))) = inner.get(1) {
                                        name = Some(n.clone());
                                    }
                                } else if key == "public_name" && inner.len() >= 2 {
                                    if let Some(Sexp::Atom(Atom::S(n))) = inner.get(1) {
                                        public_name = Some(n.clone());
                                    }
                                }
                            }
                        }
                    }

                    // Index by all existing names (ie name and, if set, public_name)
                    if let Some(n) = name {
                        self.library_index.insert(n, dune_file.clone());
                    }
                    if let Some(pn) = public_name {
                        self.library_index.insert(pn, dune_file.clone());
                    }
                }
            }
            // Recursively process nested structures (for executables, etc.)
            // Looks like this is where false positives for cyclical dependencies come from.
            for item in list {
                self.index_library_from_sexp(item, dune_file);
            }
        }
    }

    /// Part of the quick walking of the src tree - we can already spot the targets as we go.
    fn extract_executables_from_sexp(&mut self, sexp: &Sexp, dune_file: &PathBuf) {
        if let Sexp::List(list) = sexp {
            if let Some(Sexp::Atom(Atom::S(s))) = list.first() {
                if s == "executable" || s == "executables" {
                    let mut name: Option<String> = None;
                    let mut public_name: Option<String> = None;
                    let mut package: Option<String> = None;
                    let mut enabled = true;

                    for item in list.iter().skip(1) {
                        if let Sexp::List(inner) = item {
                            if let Some(Sexp::Atom(Atom::S(key))) = inner.first() {
                                match key.as_str() {
                                    "name" => {
                                        if inner.len() >= 2 {
                                            if let Some(Sexp::Atom(Atom::S(n))) = inner.get(1) {
                                                name = Some(n.clone());
                                            }
                                        }
                                    }
                                    "public_name" => {
                                        if inner.len() >= 2 {
                                            if let Some(Sexp::Atom(Atom::S(n))) = inner.get(1) {
                                                public_name = Some(n.clone());
                                            }
                                        }
                                    }
                                    "package" => {
                                        if inner.len() >= 2 {
                                            if let Some(Sexp::Atom(Atom::S(n))) = inner.get(1) {
                                                package = Some(n.clone());
                                            }
                                        }
                                    }
                                    "enabled_if" => {
                                        // Check if it's (enabled_if false)
                                        if inner.len() >= 2 {
                                            if let Some(Sexp::Atom(Atom::S(val))) = inner.get(1) {
                                                if val == "false" {
                                                    enabled = false;
                                                }
                                            }
                                        }
                                    }
                                    "names" => {
                                        // Handle (executables ((names (exe1 exe2 ...))))
                                        if inner.len() >= 2 {
                                            if let Some(Sexp::List(names_list)) = inner.get(1) {
                                                for name_item in names_list {
                                                    if let Sexp::Atom(Atom::S(n)) = name_item {
                                                        // Process each name in the list
                                                        if enabled {
                                                            let dune_path = dune_file.strip_prefix(&self.root_dir)
                                                                .unwrap_or(dune_file)
                                                                .to_string_lossy()
                                                                .to_string();
                                                            let pkg = package.clone().unwrap_or_else(|| "unknown".to_string());
                                                            self.executable_targets.push(TargetInfo {
                                                                name: n.clone(),
                                                                path: dune_path.clone(),
                                                                package: pkg.clone(),
                                                                public_name: None,
                                                            });
                                                        }
                                                    }
                                                }
                                                return; // Already processed names, don't process as single executable
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    // If we found a name, add it as a target
                    if let Some(n) = name {
                        if enabled {
                            let dune_path = dune_file.strip_prefix(&self.root_dir)
                                .unwrap_or(dune_file)
                                .to_string_lossy()
                                .to_string();
                            let pkg = package.unwrap_or_else(|| "unknown".to_string());
                            self.executable_targets.push(TargetInfo {
                                name: n,
                                path: dune_path,
                                package: pkg,
                                public_name: public_name.map(|s| s.to_string()),
                            });
                        }
                    }
                }
            }
            // Recursively process nested structures
            for item in list {
                self.extract_executables_from_sexp(item, dune_file);
            }
        }
    }

    fn parse_dune_file(&self, dune_path: &PathBuf) -> Result<Vec<Sexp>> {
        let content = std::fs::read_to_string(dune_path)
            .with_context(|| format!("Failed to read {}", dune_path.display()))?;

        // Bit of a hack, but couldn't figure out how else to do this:
        // A single dune file can have more than one s-expr (like when src/app/foo builds 3 exe's)
        // Wrapping the content in a list allows us to extract each item.
        let wrapped = format!("({})", content.trim());
        
        match sexp::parse(&wrapped) {
            Ok(Sexp::List(items)) => {
                // this is now pretty much the only code path
                Ok(items)
            }
            Ok(sexp) => {
                // Single S-expression
                eprintln!(">>> DEBUG: After wrapping content in a list, we still get a single expression: {content}");
                Ok(vec![sexp])
            }
            Err(_) => {
                // If wrapping doesn't work, try parsing as a single S-expression
                match sexp::parse(content.trim()) {
                    Ok(sexp) => Ok(vec![sexp]),
                    Err(e) => Err(anyhow::anyhow!(
                        "Failed to parse {}: {e:?}",
                        dune_path.display(),
                    )),
                }
            }
        }
    }

    /// @TODO this is silly, these are standalone functions...
    fn extract_libraries_from_sexp(&self, sexp: &Sexp) -> HashSet<String> {
        let mut libraries = HashSet::new();
        self.extract_libraries_recursive(sexp, &mut libraries);
        libraries
    }

    // @TODO thse functions need to be moved to standalone fn.
    fn extract_libraries_recursive(&self, sexp: &Sexp, libraries: &mut HashSet<String>) {
        if let Sexp::List(list) = sexp {
                if let Some(Sexp::Atom(Atom::S(key))) = list.first() {
                    if key == "libraries" {
                        // Extract all library names from this list
                        for item in list.iter().skip(1) {
                            if let Sexp::Atom(Atom::S(lib)) = item {
                                libraries.insert(lib.clone());
                                // Also add base name for sub-libraries like foobar.sub
                                if let Some(base) = lib.split('.').next() {
                                    libraries.insert(base.to_string());
                                }
                            }
                        }
                    }
                }
            for item in list {
                self.extract_libraries_recursive(item, libraries);
            }
        }
    }

    fn extract_library_names_from_sexp(&self, sexp: &Sexp) -> Option<(Option<String>, Option<String>)> {
        if let Sexp::List(list) = sexp {
            if let Some(Sexp::Atom(Atom::S(key))) = list.first() {
                if key == "library" {
                    let mut name = None;
                    let mut public_name = None;
                    // check lib stanza for names
                    for item in list.iter().skip(1) {
                        if let Sexp::List(inner) = item {
                            if let Some(Sexp::Atom(Atom::S(key))) = inner.first() {
                                match key.as_str() {
                                    "name" => {
                                        if inner.len() >= 2 {
                                            if let Some(Sexp::Atom(Atom::S(n))) = inner.get(1) {
                                                name = Some(n.clone());
                                            }
                                        }
                                    }
                                    "public_name" => {
                                        if inner.len() >= 2 {
                                            if let Some(Sexp::Atom(Atom::S(pn))) = inner.get(1) {
                                                public_name = Some(pn.clone());
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    return Some((name, public_name));
                }
            }
            // and same as the exe's: recursively check structures.
            // @TODO de-duplicate this code - should be doable
            for item in list {
                if let Some(result) = self.extract_library_names_from_sexp(item) {
                    return Some(result);
                }
            }
        }
        None
    }

    fn find_library_dune(&self, lib_name: &str) -> Option<PathBuf> {
        // First check the pre-built index
        if let Some(dune_file) = self.library_index.get(lib_name) {
            return Some(dune_file.clone());
        }

        // Handle sub-libraries - check if base library exists
        if let Some((base, sub)) = lib_name.split_once('.') {
            // Check if the base library exists and has a subdirectory
            if let Some(base_dune) = self.library_index.get(base) {
                let sub_dune = base_dune.parent().unwrap().join(sub).join("dune");
                if sub_dune.exists() {
                    return Some(sub_dune);
                }
            }
        }

        None
    }

    fn is_opam_package(&self, lib_name: &str) -> bool {
        // If we can't find a dune file for this library in the project, it's most likely an external/opam package
        // but track it, because this could also indicate a missing dependency, part of the final
        // output.
        self.find_library_dune(lib_name).is_none()
    }

    fn build_lib_tree(
        &mut self,
        lib_name: &str,
        processing: &mut HashSet<String>,
        expand: bool, // Whether to expand this library or just show it as (skip)
        level: usize, // Current depth level
        max_level: Option<usize>, // Maximum depth to resolve
    ) -> Option<DependencyNode> {
        // First, check for cycles - If we're currently already processing the lib, we have
        // cyclical dependencies (which is valid, but we need to break out to avoid deadlocks).
        //
        // This must be checked before expanded_libs to catch cycles even if the library
        // was previously expanded in a different branch of the tree
        if processing.contains(lib_name) {
            return Some(DependencyNode {
                name: format!("{lib_name} (cycle)"),
                node_type: "library".to_string(),
                path: "circular dependency".to_string(),
                dependencies: vec![],
            });
        }

        // Track this as a dependency
        self.all_dependencies.insert(lib_name.to_string());
        
        // Check if it's external/opam and track it
        // This is to report missing deps mostly - opam deps are noise, we can probably
        // filter common ones out, or look for opam files.
        if self.is_opam_package(lib_name) {
            self.external_dependencies.insert(lib_name.to_string());
        }

        // If this library has already been expanded in output, just show it as (skip)
        // But only if we're not currently processing it (which would be a cycle, caught above)
        if !expand && self.expanded_libs.contains(lib_name) {
            return Some(DependencyNode {
                name: format!("{lib_name} (skip)"),
                node_type: "library".to_string(),
                path: "already expanded".to_string(),
                dependencies: vec![],
            });
        }

        // Check if we've already fully processed this library (use cache)
        if self.visited_libs.contains(lib_name) {
            let cached_deps = self.dependency_cache.get(lib_name).cloned();
            if let Some(cached_deps) = cached_deps {
                // If we should expand, build full tree; otherwise just show as skip
                if expand {
                    self.expanded_libs.insert(lib_name.to_string());
                    // Check if we've reached max level (only if max_level is Some, not None)
                    if let Some(max) = max_level {
                        if level >= max {
                            return Some(DependencyNode {
                                name: format!("{lib_name} (max level)"),
                                node_type: "library".to_string(),
                                path: "max depth reached".to_string(),
                                dependencies: vec![],
                            });
                        }
                    }
                    // If max_level is None, continue resolving (no limit)
                    let mut child_deps = Vec::new();
                    for dep in cached_deps {
                        if !self.is_opam_package(&dep) {
                            if let Some(dep_tree) = self.build_lib_tree(&dep, processing, false, level + 1, max_level) {
                                child_deps.push(dep_tree);
                            }
                        }
                    }
                    return Some(DependencyNode {
                        name: lib_name.to_string(),
                        node_type: "library".to_string(),
                        path: "cached".to_string(),
                        dependencies: child_deps,
                    });
                } else {
                    return Some(DependencyNode {
                        name: format!("{lib_name} (skip)"),
                        node_type: "library".to_string(),
                        path: "already expanded".to_string(),
                        dependencies: vec![],
                    });
                }
            }
        }

        // Add to the map of processing libs
        processing.insert(lib_name.to_string());

        let dune_file = match self.find_library_dune(lib_name) {
            Some(f) => f,
            None => {
                // not found -> Remove from processing, add to the list of checked libs
                // but mark as external (OPAM/missing)
                processing.remove(lib_name);
                self.visited_libs.insert(lib_name.to_string());
                return Some(DependencyNode {
                    name: lib_name.to_string(),
                    node_type: "library (external)".to_string(),
                    path: "external".to_string(),
                    dependencies: vec![],
                });
            }
        };

        let sexps = match self.parse_dune_file(&dune_file) {
            Ok(s) => s,
            Err(e) => {
                // should probably just panic
                eprintln!("Failed to parse dune file {e}");
                processing.remove(lib_name);
                self.visited_libs.insert(lib_name.to_string());
                return Some(DependencyNode {
                    name: lib_name.to_string(),
                    node_type: "library".to_string(),
                    path: dune_file.display().to_string(),
                    dependencies: vec![],
                });
            }
        };

        // Get the name of the lib we're processing.
        // this is a bit of a HACK to get the many cycle entries for libs being processed filtered
        // out, but is important for sub-libs.
        let mut library_own_names = HashSet::new();
        library_own_names.insert(lib_name.to_string());
        // check base.
        if let Some(base) = lib_name.split('.').next() {
            library_own_names.insert(base.to_string());
        }
        // Add all names (subs, public_name, name)
        for sexp in &sexps {
            if let Some((name, public_name)) = self.extract_library_names_from_sexp(sexp) {
                if let Some(n) = name {
                    library_own_names.insert(n);
                }
                if let Some(pn) = &public_name {
                    library_own_names.insert(pn.clone());
                    // Also add base name for sub-libraries
                    if let Some(base) = pn.split('.').next() {
                        library_own_names.insert(base.to_string());
                    }
                }
            }
        }

        let mut all_deps = HashSet::new();
        // just build the deps.
        for sexp in &sexps {
            let deps = self.extract_libraries_from_sexp(sexp);
            all_deps.extend(deps);
        }

        // But remove the known/own names.
        for own_name in &library_own_names {
            all_deps.remove(own_name);
        }

        // This isn't really caching the deps, but it's useful nevertheless
        // Right now we're not using this cache as much as we could but if we graph per target,
        // this comes in handy.
        self.dependency_cache.insert(lib_name.to_string(), all_deps.clone());

        // Do we have a max_level, and if so: have we reached it?
        if let Some(max) = max_level {
            if level >= max {
                return Some(DependencyNode {
                    name: lib_name.to_string(),
                    node_type: "library".to_string(),
                    path: dune_file.display().to_string(),
                    dependencies: vec![],
                });
            }
        }

        let mut child_deps = Vec::new();
        for dep in all_deps {
            // Don't list opam/missing ones.
            if self.is_opam_package(&dep) {
                continue;
            }

            // For now, we only expand the libs once, for a manageable graph. maybe change this
            // behaviour with flags?
            let should_expand = !self.expanded_libs.contains(&dep);
            if let Some(dep_tree) = self.build_lib_tree(&dep, processing, should_expand, level + 1, max_level) {
                child_deps.push(dep_tree);
            }
        }

        // Add to the visited libs (ie mark as processed).
        self.visited_libs.insert(lib_name.to_string());
        // if this was the first time, mark as expanded.
        if expand {
            self.expanded_libs.insert(lib_name.to_string());
        }
        // Finally, we're done processing, so remove it.
        processing.remove(lib_name);

        Some(DependencyNode {
            name: lib_name.to_string(),
            node_type: "library".to_string(),
            path: dune_file.display().to_string(),
            dependencies: child_deps,
        })
    }

    fn build_dependency_tree(&mut self, target: &TargetInfo, max_level: Option<usize>) -> Result<DependencyNode> {
        let dune_file = self.root_dir.join(&target.path);
        let sexps = self.parse_dune_file(&dune_file)?;

        // Extract libraries for this specific executable
        let mut all_libs = HashSet::new();
        for sexp in &sexps {
            let libs = self.extract_libraries_from_sexp(sexp);
            all_libs.extend(libs);
        }

        // Also check lib/dune if it exists
        let lib_dune = dune_file.parent().unwrap().join("lib").join("dune");
        if lib_dune.exists() {
            let lib_sexps = self.parse_dune_file(&lib_dune)?;
            for sexp in &lib_sexps {
                let libs = self.extract_libraries_from_sexp(sexp);
                all_libs.extend(libs);
            }
        }

        let mut dependencies = Vec::new();
        
        // If level is 0, don't show any dependencies - just the target itself
        if let Some(0) = max_level {
            // Still track external dependencies even at level 0
            for lib in all_libs {
                if self.is_opam_package(&lib) {
                    self.external_dependencies.insert(lib.clone());
                }
            }
        } else {
            let mut processing = HashSet::new();
            for lib in all_libs {
                // Track external dependencies even if we skip them
                if self.is_opam_package(&lib) {
                    self.external_dependencies.insert(lib.clone());
                    continue;
                }

                // Always expand direct dependencies of executables (ie lvl 1)
                if let Some(dep_tree) = self.build_lib_tree(&lib, &mut processing, true, 1, max_level) {
                    dependencies.push(dep_tree);
                }
            }
        }

        Ok(DependencyNode {
            name: target.name.clone(),
            node_type: "executable".to_string(),
            path: target.path.clone(),
            dependencies,
        })
    }

    fn analyze(&mut self, target_filter: Option<&str>, use_pattern: bool, max_level: Option<usize>) -> Result<AnalysisResult> {
        // Start by simply walking the tree - building an idx.
        self.build_library_index()?;

        // Apply --target filter if specified.
        let mut targets = self.executable_targets.clone();
        if let Some(filter) = target_filter {
            if use_pattern {
                targets.retain(|t| t.name.contains(filter));
                eprintln!("Filtered to targets matching pattern: {filter}");
            } else {
                targets.retain(|t| t.name == filter);
                eprintln!("Filtered to target: {filter}");
            }
        }
        
        eprintln!("Found {} executable targets", targets.len());

        if let Some(level) = max_level {
            eprintln!("Resolving dependencies to level {level}");
        } else {
            eprintln!("Resolving full dependency tree (no level limit)");
        }

        eprintln!("Building dependency graphs...");
        let mut dependency_graphs = HashMap::new();

        for target in &targets {
            eprintln!("  Analyzing {}...", target.name);
            // Clear expanded_libs for each target so we can see full graph for each target's direct deps
            // But keep visited_libs and dependency_cache to avoid re-parsing
            self.expanded_libs.clear();
            let tree = self.build_dependency_tree(target, max_level)?;
            dependency_graphs.insert(target.name.clone(), tree);
        }

        // Convert all_dependencies to sorted vector
        let mut all_unique_deps: Vec<String> = self.all_dependencies.iter().cloned().collect();
        all_unique_deps.sort();

        // Convert external_dependencies to sorted vector
        let mut external_deps: Vec<String> = self.external_dependencies.iter().cloned().collect();
        external_deps.sort();

        Ok(AnalysisResult {
            targets,
            dependency_graphs,
            all_unique_dependencies: all_unique_deps,
            external_dependencies: external_deps,
        })
    }
}

fn main() -> Result<()> {

    let args = Args::parse();
    let root = args.root.canonicalize()?;
    let mut analyzer = DependencyAnalyzer::new(root);

    let result = analyzer.analyze(args.target.as_deref(), args.pattern, args.level)?;

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        output_text(&result, args);
    }

    Ok(())
}

fn output_text(result: &AnalysisResult, args: Args) {
    println!("{}", "=".repeat(80));
    println!("BUILD TARGETS");
    println!("{}", "=".repeat(80));
    for target in &result.targets {
        println!("\n{}", target.name);
        println!("  Path: {}", target.path);
        println!("  Package: {}", target.package);
        if let Some(ref public_name) = target.public_name {
            println!("  Public name: {public_name}");
        }
    }
    println!("{}", "=".repeat(80));

    if args.full_graph {
        println!("\n{}", "=".repeat(80));
        println!("DEPENDENCY GRAPHS (Detailed)");
        println!("{}", "=".repeat(80));

        for (target_name, tree) in &result.dependency_graphs {
            println!("\n{} ({}):", target_name, tree.node_type);
            print_tree(tree, 2);
        }
    }

    if args.unique_list {
        println!("\n{}", "=".repeat(80));
        println!("UNIQUE DEPENDENCIES");
        println!("{}", "=".repeat(80));
        println!("Total: {}", result.all_unique_dependencies.len());
        for dep in &result.all_unique_dependencies {
            println!("  - {dep}");
        }
    }

    println!("\n{}", "=".repeat(80));
    println!("OPAM OR MISSING");
    println!("{}", "=".repeat(80));
    println!("Total: {}", result.external_dependencies.len());
    println!("These dependencies were not found in the project and are assumed to be opam packages.");
    println!("Please verify they are opam dependencies, or add them to the project if missing:");
    for dep in &result.external_dependencies {
        println!("  - {dep}");
    }
}

fn print_tree(node: &DependencyNode, indent: usize) {
    let spaces = " ".repeat(indent);
    println!("{}* {} ({})", spaces, node.name, node.node_type);
    if !node.path.is_empty() && node.path != "external" {
        println!("{}  [{}]", spaces, node.path);
    }

    for dep in &node.dependencies {
        print_tree(dep, indent + 2);
    }
}
