from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"))
from secure_llm.hardware import detect_hardware
def main():
 report=detect_hardware();path=ROOT/"reports"/"local_hardware.json";path.parent.mkdir(exist_ok=True);path.write_text(json.dumps(report,indent=2),encoding="utf-8");print(json.dumps(report,indent=2))
if __name__=="__main__":main()
