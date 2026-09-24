Record content corpus for internal/validate (table tests and fuzz seeds).
Format: one case per line, `TYPE<TAB>CONTENT`; `#` starts a comment line.
valid.txt holds content that must be accepted, invalid.txt content that must be
refused before PowerDNS (research D5). Control characters, CR/LF and zone-file
directives are exercised by the Go tests directly (they cannot live on one line).
