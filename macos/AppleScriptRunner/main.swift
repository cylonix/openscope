// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import AppKit
import Foundation

struct Request: Decodable {
    let scriptPath: String
    let params: [String: String]
}

struct RunnerError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

func decodeRequest() throws -> Request {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    if data.isEmpty {
        throw RunnerError(message: "missing runner request on stdin")
    }

    do {
        return try JSONDecoder().decode(Request.self, from: data)
    } catch {
        throw RunnerError(message: "decode runner request: \(error.localizedDescription)")
    }
}

func render(source: String, params: [String: String]) -> String {
    var rendered = source
    for (key, value) in params {
        rendered = rendered.replacingOccurrences(of: "{{\(key)}}", with: appleScriptStringLiteral(value))
    }
    return rendered
}

func appleScriptStringLiteral(_ value: String) -> String {
    var escaped = value
    escaped = escaped.replacingOccurrences(of: "\\", with: "\\\\")
    escaped = escaped.replacingOccurrences(of: "\"", with: "\\\"")
    return "\"\(escaped)\""
}

func stringValue(from descriptor: NSAppleEventDescriptor?) -> String {
    guard let descriptor else {
        return ""
    }

    if let stringValue = descriptor.stringValue {
        return stringValue
    }

    if descriptor.descriptorType == typeNull {
        return ""
    }

    return descriptor.description
}

func format(error: NSDictionary) -> String {
    if let message = error[NSAppleScript.errorMessage] as? String {
        return message
    }
    return error.description
}

do {
    let request = try decodeRequest()
    let source = try String(contentsOfFile: request.scriptPath, encoding: .utf8)
    let rendered = render(source: source, params: request.params)

    var executeError: NSDictionary?
    guard let script = NSAppleScript(source: rendered) else {
        throw RunnerError(message: "failed to create NSAppleScript instance")
    }

    let result = script.executeAndReturnError(&executeError)
    if let executeError {
        throw RunnerError(message: format(error: executeError))
    }

    print(stringValue(from: result))
} catch {
    fputs("\(error.localizedDescription)\n", stderr)
    exit(1)
}
