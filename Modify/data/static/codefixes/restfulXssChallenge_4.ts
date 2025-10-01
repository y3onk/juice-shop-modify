"// Import at top of the file if not present:
// import { SecurityContext } from '@angular/core';

trustProductDescription(tableData: any[]) {
  for (let i = 0; i < tableData.length; i++) {
    const raw = tableData[i].description;
    // Sanitize as HTML and store the safe string. Do NOT use any bypass* APIs.
    const safe = this.sanitizer.sanitize(SecurityContext.HTML, raw) ?? '';
    tableData[i].description = safe;
  }
}
"