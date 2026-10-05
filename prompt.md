> **Train and integrate a high-performance NLP threat detection model for HoneyPrompt using the dataset located at:**
> 
> 
> `C:\Users\HP\OneDrive\Desktop\HoneyPrompt_AI_Intrusion_Detection_System_AI_IDS_for_Commercial_Chatbots\Dataset`
> 
> 
> **Do not rebuild, remove, or break the existing HoneyPrompt application.** First inspect the existing project structure, backend, frontend, database, APIs, and current detection logic, then integrate the trained model into the existing architecture.
> 
> 
> 
> ### 1. Dataset Preparation
> 
> 
> - Inspect all files inside the `Dataset` folder and automatically identify the relevant training files and columns.
> - Determine which columns contain the **prompt/text** and **label/category**.
> - Show dataset size, columns, missing values, duplicate samples and class distribution before training.
> - Clean empty, corrupted and duplicate prompts.
> - Normalize text carefully without destroying important adversarial patterns.
> - Check for class imbalance.
> - Remove data leakage and near-duplicate samples between train/validation/test.
> 
> 
> ### 2. Classification
> 
> Build a proper model capable of distinguishing:
> 
> 
> 🟢 **SAFE** — legitimate/normal prompts
> 
> 🟡 **SUSPICIOUS** — probing, unusual or uncertain security-related prompts
> 
> 🔴 **MALICIOUS** — adversarial, unauthorized or harmful prompts
> 
> 
> Where the dataset supports it, identify:
> 
> 
> 
> - Prompt Injection
> - Jailbreak
> - System Prompt Extraction
> - Credential Extraction
> - Role Manipulation
> - Privilege Escalation
> - Data Exfiltration
> - Security Policy Bypass
> - Harmful Request
> 
> **Do not fabricate labels that do not exist in the dataset.** If the dataset only supports binary classification, train the primary model on the available labels and create a separate properly labeled extension for the additional categories.
> 
> 
> 
> ### 3. Model Training
> 
> Use a strong NLP approach, preferably a **fine-tuned DistilBERT/BERT transformer**, rather than relying only on keywords or simple regex rules.
> 
> 
> Pipeline:
> 
> 
> `Dataset → Cleaning → Deduplication → Label Validation → Stratified Split → Tokenization → Fine-Tuning → Validation → Evaluation → Best Model Saving`
> 
> 
> Use:
> 
> 
> 
> - Stratified train/validation/test split
> - Class weighting or suitable sampling if required
> - Early stopping
> - Learning-rate scheduling
> - Appropriate batch size
> - Weight decay
> - Best-model checkpointing
> 
> Optimize particularly for **malicious-prompt recall**, because missing an actual attack is more serious than a false positive.
> 
> 
> 
> ### 4. Evaluation
> 
> Generate:
> 
> 
> 
> - Accuracy
> - Precision
> - Recall
> - F1-score
> - ROC-AUC where applicable
> - Confusion matrix
> - Per-class metrics
> - False-positive rate
> - False-negative rate
> 
> Test the model on unseen examples and adversarial/paraphrased prompts.
> 
> 
> 
> ### 5. Dynamic Confidence
> 
> **Never use a fixed confidence such as 97%, 98% or 99%.**
> 
> 
> Confidence must come from the actual model prediction for each prompt.
> 
> 
> If appropriate, calibrate the model probabilities using a validation set.
> 
> 
> Generate a dynamic result such as:
> 
> 
> 
> ```
> {
> "classification": "MALICIOUS",
> "threat_type": "PROMPT_INJECTION",
> "severity": "HIGH",
> "confidence": 0.94,
> "risk_score": 91,
> "action": "BLOCKED"
> }
> ```
> 
> 
> ### 6. HoneyPrompt Risk Engine
> 
> Combine the trained ML model with carefully designed rule/pattern detection so the system can catch both known and paraphrased attacks.
> 
> 
> Architecture:
> 
> 
> `User Prompt`
> 
> ↓
> 
> `Preprocessing`
> 
> ↓
> 
> `ML Threat Classifier`
> 
> +
> 
> `Security Rules / Indicators`
> 
> ↓
> 
> `Risk Scoring`
> 
> ↓
> 
> `SAFE / SUSPICIOUS / MALICIOUS`
> 
> ↓
> 
> `Threat Type + Severity + Confidence`
> 
> ↓
> 
> `ALLOWED / MONITORED / BLOCKED`
> 
> ↓
> 
> `LLM`
> 
> 
> **The user's prompt must be analyzed independently of the LLM response.**
> 
> 
> Do not classify a malicious prompt as SAFE simply because the LLM responds with:
> 
> 
> `I'm sorry, but I can't help with that.`
> 
> 
> 
> ### 7. Integration With Existing Backend
> 
> Integrate the trained model into the existing HoneyPrompt backend without breaking existing APIs.
> 
> 
> Load the trained model **once when the backend starts**, not for every request.
> 
> 
> Update the existing `/api/chat` flow so the security analysis happens before the LLM request.
> 
> 
> For:
> 
> 
> **SAFE →** allow LLM request
> 
> **SUSPICIOUS →** allow/monitor and record security event
> 
> **MALICIOUS →** block request and return security response
> 
> 
> 
> ### 8. Frontend
> 
> Update the existing HoneyPrompt UI to display the **actual backend values dynamically**:
> 
> 
> 
> - 🟢/🟡/🔴 Classification
> - Threat Type
> - Severity
> - Confidence
> - Risk Score
> - Action
> - Reason
> 
> Remove any hardcoded/default:
> 
> 
> `SAFE`
> 
> `Normal Query`
> 
> `97%`
> 
> `ALLOWED`
> 
> 
> values.
> 
> 
> 
> ### 9. Testing
> 
> Create a comprehensive test suite containing:
> 
> 
> 
> - Normal conversations
> - General questions
> - Security education
> - Security probing
> - Prompt injection
> - Jailbreak attempts
> - System prompt extraction
> - Credential extraction
> - Role manipulation
> - Privilege escalation
> - Data exfiltration
> - Harmful requests
> - Obfuscated prompts
> - Paraphrased attacks
> - Previously unseen attack variations
> 
> Verify that the classifier does **not simply depend on exact keywords**.
> 
> 
> 
> ### 10. Training Report
> 
> Save a training report containing:
> 
> 
> 
> - Dataset size
> - Dataset classes
> - Class distribution
> - Train/validation/test sizes
> - Training configuration
> - Best epoch
> - Final metrics
> - Confusion matrix
> - Precision/Recall/F1
> - False positives
> - False negatives
> - Example predictions
> 
> Save the final trained model and tokenizer in a dedicated model directory inside the existing project.
> 
> 
> **Important:** First inspect the dataset and existing HoneyPrompt codebase before making changes. Reuse existing architecture wherever possible. Do not delete or replace working features. The final system must use the trained model for real-time prompt analysis and must produce different classifications and confidence values based on the actual input.