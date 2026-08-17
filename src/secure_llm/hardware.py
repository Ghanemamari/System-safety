from __future__ import annotations
import platform
from typing import Any

def detect_hardware() -> dict[str, Any]:
    import psutil,torch,transformers
    cuda=torch.cuda.is_available();gpu_name=torch.cuda.get_device_name(0) if cuda else None
    vram=round(torch.cuda.get_device_properties(0).total_memory/1024**3,2) if cuda else 0.0
    return {"cuda_available":cuda,"gpu_name":gpu_name,"gpu_vram_gb":vram,"system_ram_gb":round(psutil.virtual_memory().total/1024**3,2),"pytorch_version":torch.__version__,"transformers_version":transformers.__version__,"python":platform.python_version(),"platform":platform.platform(),"recommended_device":"auto" if cuda else "cpu","quantization_default":None}
