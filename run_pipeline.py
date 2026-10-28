import sys
import os

# Add src to pythonpath
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from threatmoni.pipeline import ThreatMoniPipeline

def main():
    pipeline = ThreatMoniPipeline()
    pipeline.run()

if __name__ == "__main__":
    main()
