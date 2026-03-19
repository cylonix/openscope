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

set target_folder_name to {{folder}}
set target_note_name to {{note}}

tell application "Notes"
	set target_folder to first folder whose name is target_folder_name
	set target_note to first note of target_folder whose name is target_note_name
	set note_title to name of target_note
	set note_body to body of target_note
end tell

return "{\"folder\":\"" & json_escape(target_folder_name) & "\",\"title\":\"" & json_escape(note_title) & "\",\"body\":\"" & json_escape(note_body) & "\"}"
