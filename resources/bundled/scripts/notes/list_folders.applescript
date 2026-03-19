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

tell application "Notes"
	set folder_names to name of every folder
end tell

set json_items to {}
repeat with folder_name in folder_names
	set end of json_items to "\"" & json_escape(folder_name as text) & "\""
end repeat

return "[" & join_with(json_items, ",") & "]"
