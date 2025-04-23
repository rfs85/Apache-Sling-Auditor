#!/usr/bin/env python3
"""
Path Generator for Apache Sling Enumeration
This script generates additional paths by combining base paths with extensions and parameters
"""

import itertools
from pathlib import Path

def read_wordlist(filename):
    """Read the wordlist and categorize entries"""
    paths = []
    extensions = []
    parameters = []
    
    current_category = None
    
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                if 'Extensions' in line:
                    current_category = 'extensions'
                elif 'Parameters' in line:
                    current_category = 'parameters'
                else:
                    current_category = 'paths'
                continue
            
            if current_category == 'extensions':
                if line.startswith('.'):
                    extensions.append(line)
            elif current_category == 'parameters':
                if line.startswith('?'):
                    parameters.append(line)
            else:
                if line.startswith('/'):
                    paths.append(line)
    
    return paths, extensions, parameters

def generate_combinations(paths, extensions, parameters):
    """Generate combinations of paths with extensions and parameters"""
    combinations = set()
    
    # Add base paths
    combinations.update(paths)
    
    # Add paths with extensions
    for path, ext in itertools.product(paths, extensions):
        if not path.endswith(ext):
            combinations.add(f"{path}{ext}")
    
    # Add paths with parameters
    for path, param in itertools.product(paths, parameters):
        combinations.add(f"{path}{param}")
    
    # Add paths with both extensions and parameters
    for path, ext, param in itertools.product(paths, extensions, parameters):
        if not path.endswith(ext):
            combinations.add(f"{path}{ext}{param}")
    
    return sorted(combinations)

def main():
    wordlist_file = Path(__file__).parent / 'sling_paths.txt'
    output_file = Path(__file__).parent / 'sling_paths_generated.txt'
    
    # Read the base wordlist
    paths, extensions, parameters = read_wordlist(wordlist_file)
    
    # Generate combinations
    all_paths = generate_combinations(paths, extensions, parameters)
    
    # Write the expanded wordlist
    with open(output_file, 'w') as f:
        for path in all_paths:
            f.write(f"{path}\n")
    
    print(f"Generated {len(all_paths)} unique paths")
    print(f"Wordlist saved to {output_file}")

if __name__ == '__main__':
    main() 