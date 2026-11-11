"""Turns an uploaded draw.io diagram into positioned nodes for the network map page."""
import os
import re
from html import unescape

def parse_network_map(map_file):
    if not os.path.exists(map_file):
        return []

    try:
        with open(map_file, 'r', encoding='utf-8') as f:
            content = f.read()

        nodes = []

        # Find all vertex cells with x and y coordinates
        # Pattern looks for mxCell with vertex=1 that has x= and y= attributes directly
        cells = re.findall(r'<mxCell([^>]*vertex="1"[^>]*x="[0-9]+"[^>]*y="[0-9]+"[^>]*)>', content)

        for cell in cells:
            value_match = re.search(r'value="([^"]+)"', cell)
            x_match = re.search(r'x="([^"]+)"', cell)
            y_match = re.search(r'y="([^"]+)"', cell)
            style_match = re.search(r'style="([^"]+)"', cell)

            if not (value_match and x_match and y_match):
                continue

            value = value_match.group(1)
            x = x_match.group(1)
            y = y_match.group(1)
            style = style_match.group(1) if style_match else ''

            # Unescape HTML entities
            value = unescape(value)
            # Remove HTML tags
            clean_value = re.sub(r'<[^>]+>', '', value).strip()

            if not clean_value or len(clean_value) < 3:
                continue

            node_type = 'internal'
            style_lower = style.lower()

            if 'dashed' in style_lower or 'perimeter' in style_lower:
                node_type = 'dmz'
            elif 'rounded' in style_lower or 'shape=process' in style_lower:
                node_type = 'dmz'
            elif 'rhombus' in style_lower:
                node_type = 'dmz'
            elif 'ellipse' in style_lower:
                node_type = 'internal'

            try:
                x_pos = int(x) // 3
                y_pos = int(y) // 3
            except ValueError:
                x_pos = 100
                y_pos = 100

            nodes.append({
                'label': clean_value[:25],
                'ip': clean_value if '.' in clean_value and re.match(r'^[\d.]+$', clean_value) else '',
                'type': node_type,
                'x': max(50, min(x_pos, 750)),
                'y': max(50, min(y_pos, 450))
            })

        # If we have very few nodes, try extracting all IPs from the diagram
        if len(nodes) < 5:
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, content)
            seen = set()
            for ip in ips:
                if ip not in seen and len(nodes) < 20:
                    seen.add(ip)
                    nodes.append({
                        'label': ip,
                        'ip': ip,
                        'type': 'internal',
                        'x': 100 + len(nodes) * 90,
                        'y': 200 + (len(nodes) % 3) * 100
                    })

        return nodes[:30]
    except Exception as e:
        print(f"Error parsing XML: {e}")
        return [{'label': 'Error', 'ip': '', 'type': 'internal', 'x': 300, 'y': 250}]
