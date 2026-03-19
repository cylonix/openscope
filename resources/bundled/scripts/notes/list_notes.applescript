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

set target_folder_name to {{folder}}

tell application "Notes"
	set target_folder to first folder whose name is target_folder_name
	set target_notes to every note of target_folder
end tell

set json_items to {}
repeat with target_note in target_notes
	tell application "Notes"
		set note_title to name of target_note
	end tell
	set end of json_items to "{\"title\":\"" & json_escape(note_title) & "\"}"
end repeat

return "[" & join_with(json_items, ",") & "]"
