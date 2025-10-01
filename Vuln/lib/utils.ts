export const containsEscaped = function (str: string, element: string) {
  return contains(str, element.replace(/"/g, '\\"'))
}