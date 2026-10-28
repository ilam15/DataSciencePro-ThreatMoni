import sys
import os

# Ensure src/ is in Python path for execution from project root or scripts/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from threatmoni.pipeline import ThreatMoniPipeline

def main():
    pipeline = ThreatMoniPipeline()
    pipeline.run()

if __name__ == "__main__":
    main()
