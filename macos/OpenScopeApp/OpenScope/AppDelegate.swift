// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import AppKit
import Foundation

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        launchAscopedIfNeeded()
        // Probe Notes Automation permission after a short delay so the run loop
        // is fully started. NSAppleScript must run on the main thread; it blocks
        // until the user responds to the TCC prompt, then we quit.
        perform(#selector(requestNotesPermissionAndQuit), with: nil, afterDelay: 0.5)
    }

    @objc private func requestNotesPermissionAndQuit() {
        requestNotesAutomationPermission()
        NSApp.terminate(nil)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    private func requestNotesAutomationPermission() {
        // This call blocks the main thread until the user responds to the
        // macOS "OpenScope wants to control Notes" prompt (or immediately
        // returns if permission was already granted or denied).
        guard let script = NSAppleScript(source: "tell application \"Notes\" to return") else { return }
        var error: NSDictionary?
        script.executeAndReturnError(&error)
    }

    private func launchAscopedIfNeeded() {
        guard let resourcePath = Bundle.main.resourcePath else {
            NSLog("OpenScope: missing bundle resource path")
            return
        }

        let binaryURL = URL(fileURLWithPath: resourcePath)
            .appendingPathComponent("bin", isDirectory: true)
            .appendingPathComponent("openscoped", isDirectory: false)

        guard FileManager.default.isExecutableFile(atPath: binaryURL.path) else {
            NSLog("OpenScope: openscoped not found at %@", binaryURL.path)
            return
        }

        let process = Process()
        process.executableURL = binaryURL

        var env = ProcessInfo.processInfo.environment
        if env["HOME"] == nil, let home = FileManager.default.homeDirectoryForCurrentUser.path as String? {
            env["HOME"] = home
        }
        process.environment = env

        let devNull = FileHandle.nullDevice
        process.standardOutput = devNull
        process.standardError = devNull

        do {
            try process.run()
        } catch {
            NSLog("OpenScope: failed to launch openscoped: %@", error.localizedDescription)
        }
    }
}
