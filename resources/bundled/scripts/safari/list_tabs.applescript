on replace_text(subject, search_string, replacement_string)
	set AppleScript's text item delimiters to search_string
	set parts to every text item of subject
	set AppleScript's text item delimiters to replacement_string
	set rebuilt to parts as text
	set AppleScript's text item delimiters to ""
	return rebuilt
end replace_text

on json_escape(value_text)
	set escaped to replace_text(value_text, "\\", "\\\\")
	set escaped to replace_text(escaped, "\"", "\\\"")
	set escaped to replace_text(escaped, return, "\\n")
	set escaped to replace_text(escaped, linefeed, "\\n")
	return escaped
end json_escape

on join_with(items_list, separator_text)
	set AppleScript's text item delimiters to separator_text
	set joined to items_list as text
	set AppleScript's text item delimiters to ""
	return joined
end join_with

set json_items to {}

tell application "Safari"
	repeat with target_window in every window
		set window_index to index of target_window
		repeat with target_tab in every tab of target_window
			set tab_name to name of target_tab as text
			set tab_url to URL of target_tab as text
			set end of json_items to "{\"window\":" & window_index & ",\"title\":\"" & json_escape(tab_name) & "\",\"url\":\"" & json_escape(tab_url) & "\"}"
		end repeat
	end repeat
end tell

return "[" & join_with(json_items, ",") & "]"
