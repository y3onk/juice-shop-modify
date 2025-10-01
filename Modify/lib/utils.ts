"export const containsEscaped = function (str: string, element: string) {
  // Escape backslashes first, then double quotes to avoid double-escaping issues
  const escaped = element.replace(/\\/g, '\\\\').replace(/""/g, '\\""')
  return contains(str, escaped)
}
"
