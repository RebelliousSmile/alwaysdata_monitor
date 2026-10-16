// Mobile (scan du QR code) ou ordinateur (lien collé). Le plugin
// barcode-scanner n'existe que dans les builds Android et iOS.

export function isMobile(userAgent: string = navigator.userAgent): boolean {
  return /Android|iPhone|iPad/i.test(userAgent)
}
