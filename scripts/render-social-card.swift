// Run from the repository root: swift scripts/render-social-card.swift
// Uses macOS AppKit; the generated PNG is committed for platform-independent builds.
import AppKit

let width = 1200, height = 630
let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height,
    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
    colorSpaceName: .deviceRGB, bytesPerRow: width * 4, bitsPerPixel: 32)!
let context = NSGraphicsContext(bitmapImageRep: bitmap)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = context
func color(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat) -> NSColor {
    NSColor(srgbRed: r / 255, green: g / 255, blue: b / 255, alpha: 1)
}
let background = color(24, 28, 25), foreground = color(231, 233, 226)
let muted = color(175, 182, 173), accent = color(115, 146, 184)
background.setFill()
NSRect(x: 0, y: 0, width: width, height: height).fill()
func label(_ text: String, x: CGFloat, top: CGFloat, size: CGFloat,
           weight: NSFont.Weight = .regular, ink: NSColor) {
    let attrs: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: size, weight: weight), .foregroundColor: ink]
    let dimensions = (text as NSString).size(withAttributes: attrs)
    precondition(x + dimensions.width <= 1130, "Text exceeds safe card width")
    (text as NSString).draw(at: NSPoint(x: x, y: CGFloat(height) - top - dimensions.height), withAttributes: attrs)
}
let smile = NSImage(contentsOfFile: "static/brand-smiley.png")!
context.imageInterpolation = .none
smile.draw(in: NSRect(x: 72, y: height - 72 - 96, width: 96, height: 96))
label("Matthew Green", x: 196, top: 92, size: 38, weight: .semibold, ink: foreground)
label("DFIR & threat intel.", x: 72, top: 244, size: 66, weight: .bold, ink: foreground)
label("Research, tools & practical AI.", x: 72, top: 336, size: 48, weight: .medium, ink: accent)
color(62, 67, 62).setFill()
NSRect(x: 72, y: 115, width: 1056, height: 1).fill()
label("dfir.au · @mgreen27", x: 72, top: 539, size: 27, weight: .medium, ink: muted)
NSGraphicsContext.restoreGraphicsState()
let output = URL(fileURLWithPath: "static/social-preview.png")
try bitmap.representation(using: .png, properties: [:])!.write(to: output)
print("Wrote \(output.path) (\(width) × \(height))")
