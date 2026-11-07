"""
TRUSTX AI - Master Vector & Raster Logo Generator
Generates high-precision cybersecurity SVG and PNG icons across all resolutions.
"""

import os
from PIL import Image, ImageDraw, ImageFont

ICONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'extension', 'icons')
FRONTEND_PUBLIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frontend', 'public')
os.makedirs(ICONS_DIR, exist_ok=True)
os.makedirs(FRONTEND_PUBLIC, exist_ok=True)

SVG_CONTENT = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="100%" height="100%">
  <defs>
    <!-- Background Gradient for Subtle Depth -->
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0b1120" />
      <stop offset="100%" stop-color="#020617" />
    </linearGradient>

    <!-- Shield Rim Gradient -->
    <linearGradient id="rimGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#38bdf8" />
      <stop offset="50%" stop-color="#2563eb" />
      <stop offset="100%" stop-color="#1d4ed8" />
    </linearGradient>

    <!-- Blade 1 Cyan -->
    <linearGradient id="bladeCyan" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#38bdf8" />
      <stop offset="100%" stop-color="#0284c7" />
    </linearGradient>

    <!-- Blade 2 Blue -->
    <linearGradient id="bladeBlue" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#60a5fa" />
      <stop offset="100%" stop-color="#2563eb" />
    </linearGradient>
  </defs>

  <!-- Base Rounded Container -->
  <rect width="512" height="512" rx="110" fill="url(#bgGrad)" stroke="#1e293b" stroke-width="8"/>

  <!-- Outer Cyber Shield Contour -->
  <path d="M256,54 L410,126 L410,268 C410,364 256,448 256,448 C256,448 102,364 102,268 L102,126 Z" 
        fill="#070c18" stroke="url(#rimGrad)" stroke-width="12" stroke-linejoin="round"/>

  <!-- Inner Dark Facets (Left & Right for 3D Depth) -->
  <path d="M256,70 L394,134 L394,264 C394,348 256,428 256,428 Z" fill="#0c1527" opacity="0.6"/>
  <path d="M256,70 L118,134 L118,264 C118,348 256,428 256,428 Z" fill="#070d1a" opacity="0.9"/>

  <!-- Tactical Circuit Traces -->
  <line x1="256" y1="70" x2="256" y2="140" stroke="#1e3a8a" stroke-width="4" stroke-dasharray="6,4"/>
  <line x1="256" y1="380" x2="256" y2="430" stroke="#1e3a8a" stroke-width="4" stroke-dasharray="6,4"/>
  <circle cx="256" cy="74" r="5" fill="#38bdf8"/>
  <circle cx="118" cy="134" r="5" fill="#2563eb"/>
  <circle cx="394" cy="134" r="5" fill="#2563eb"/>

  <!-- The Interlocking TRUSTX 'X' Blades -->
  <!-- Diagonal Blade 1 (Top-Left to Bottom-Right) -->
  <polygon points="172,168 214,152 340,344 298,360" fill="url(#bladeCyan)" />
  
  <!-- Diagonal Blade 2 (Top-Right to Bottom-Left) -->
  <!-- Split into two segments to create an interlocking 3D weave effect -->
  <polygon points="340,168 298,152 274,188 296,220" fill="url(#bladeBlue)" />
  <polygon points="216,344 258,360 238,324 216,292" fill="url(#bladeBlue)" />
  <polygon points="296,220 216,292 196,262 276,190" fill="url(#bladeBlue)" opacity="0.95" />

  <!-- Central Security Core (Shield / Diamond) -->
  <polygon points="256,226 288,256 256,286 224,256" fill="#052e16" stroke="#10b981" stroke-width="6"/>
  <circle cx="256" cy="256" r="6" fill="#34d399"/>
</svg>
'''


def draw_high_res_icon(size):
    """Render the high-precision TRUSTX AI logo into an anti-aliased PIL image."""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    scale = size / 512.0
    def S(v): return v * scale
    def pt(x, y): return (x * scale, y * scale)

    # 1. Base dark rounded box
    corner_rad = int(S(110))
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=corner_rad, fill=(11, 17, 32, 255), outline=(30, 41, 59, 255), width=max(1, int(S(8))))

    # 2. Outer Shield
    shield_pts = [
        pt(256, 54),
        pt(410, 126),
        pt(410, 268),
        pt(256, 448),
        pt(102, 268),
        pt(102, 126),
    ]
    draw.polygon(shield_pts, fill=(7, 12, 24, 255), outline=(37, 99, 235, 255))
    
    # Shield border width
    border_w = max(1, int(S(10)))
    for i in range(len(shield_pts)):
        p1 = shield_pts[i]
        p2 = shield_pts[(i + 1) % len(shield_pts)]
        draw.line([p1, p2], fill=(56, 189, 248, 255) if p1[1] < S(200) else (37, 99, 235, 255), width=border_w)

    # 3. Inner 3D Facet
    facet_pts = [pt(256, 70), pt(394, 134), pt(394, 264), pt(256, 428), pt(256, 70)]
    draw.polygon(facet_pts, fill=(12, 21, 39, 255))

    # 4. Diagonal Blade 1 (Cyan: Top-Left to Bottom-Right)
    blade1 = [pt(172, 168), pt(214, 152), pt(340, 344), pt(298, 360)]
    draw.polygon(blade1, fill=(56, 189, 248, 255))

    # 5. Diagonal Blade 2 (Blue: Top-Right to Bottom-Left)
    blade2_top = [pt(340, 168), pt(298, 152), pt(274, 188), pt(316, 204)]
    blade2_bot = [pt(216, 344), pt(258, 360), pt(238, 324), pt(196, 308)]
    blade2_mid = [pt(296, 215), pt(216, 297), pt(196, 267), pt(276, 185)]
    draw.polygon(blade2_top, fill=(37, 99, 235, 255))
    draw.polygon(blade2_bot, fill=(37, 99, 235, 255))
    draw.polygon(blade2_mid, fill=(29, 78, 216, 255))

    # 6. Central Trust Core (Emerald Diamond)
    core = [pt(256, 226), pt(288, 256), pt(256, 286), pt(224, 256)]
    draw.polygon(core, fill=(5, 46, 22, 255), outline=(16, 185, 129, 255))
    
    # Core dot
    r = max(2, int(S(6)))
    cx, cy = int(S(256)), int(S(256))
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(52, 211, 153, 255))

    return img


def generate_all_icons():
    # 1. Write SVGs
    svg_paths = [
        os.path.join(ICONS_DIR, 'icon128.svg'),
        os.path.join(FRONTEND_PUBLIC, 'favicon.svg'),
        os.path.join(FRONTEND_PUBLIC, 'icons.svg'),
    ]
    for p in svg_paths:
        with open(p, 'w', encoding='utf-8') as f:
            f.write(SVG_CONTENT.strip())
        print(f"Saved SVG: {p}")

    # 2. Render PNG sizes
    sizes = [16, 32, 48, 128, 256, 512]
    for sz in sizes:
        icon = draw_high_res_icon(sz)
        
        # Save extension icons
        if sz in [16, 32, 48, 128]:
            p = os.path.join(ICONS_DIR, f'icon{sz}.png')
            icon.save(p, 'PNG')
            print(f"Saved PNG: {p}")
        
        # Save frontend public logo
        if sz == 128:
            p_fav = os.path.join(FRONTEND_PUBLIC, 'favicon.png')
            icon.save(p_fav, 'PNG')
            print(f"Saved Frontend Favicon: {p_fav}")
        
        if sz == 512:
            p_hero = os.path.join(FRONTEND_PUBLIC, 'logo512.png')
            icon.save(p_hero, 'PNG')
            print(f"Saved Logo 512: {p_hero}")


if __name__ == '__main__':
    generate_all_icons()
    print("SUCCESS: All TRUSTX AI master brand assets generated!")
