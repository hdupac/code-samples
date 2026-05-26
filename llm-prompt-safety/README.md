# LLM Prompt Safety (sample)

**Problem.** A production LLM application takes long-form user-supplied content (uploaded documents, OCR'd notes, free-form fields) and feeds it into Claude alongside system instructions. Without explicit isolation, the model can be manipulated to leak prompts, change role, or bypass output rules.

**My role.** Solo founder / sole engineer.

**Stack.** Python 3.11, Anthropic Claude. Project name and domain withheld.

**State.** Live with a paying customer, used daily on confidential data.

**One number.** Zero successful prompt-injection bypass observed in production.

The file `prompt_safety.py` is the defense-in-depth layer — one module among many in the private repo. Full codebase walkthrough available on request.
