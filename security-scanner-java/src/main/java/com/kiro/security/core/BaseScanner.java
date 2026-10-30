package com.kiro.security.core;

import java.nio.file.Path;
import java.util.List;

/**
 * Base interface for all scanner plugins.
 * Each scanner category (source-code, dependency, container, infra) implements this.
 */
public interface BaseScanner {

    /** Human-readable scanner name. */
    String getName();

    /** Category identifier (source-code, dependency, container, infrastructure). */
    String getCategory();

    /**
     * Run the scan against the target directory.
     *
     * @param targetDir path to the project to scan
     * @return list of findings
     * @throws Exception if the scan cannot complete
     */
    List<Finding> scan(Path targetDir) throws Exception;
}
