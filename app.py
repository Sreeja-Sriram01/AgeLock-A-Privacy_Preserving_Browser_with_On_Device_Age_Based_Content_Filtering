from flask import Flask, request, jsonify
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import torch
import numpy as np
from shap import KernelExplainer

app = Flask(__name__)

class ContentFilter:
    def __init__(self):
        self.tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
        self.model = DistilBertForSequenceClassification.from_pretrained('distilbert-base-uncased')
        self.model.eval()

    def predict(self, text):
        inputs = self.tokenizer(text, return_tensors='pt', padding=True, truncation=True)
        outputs = self.model(**inputs)
        return torch.softmax(outputs.logits, dim=1).detach().numpy()

    def explain(self, text):
        def model_predict(x):
            return self.predict(x)
        
        explainer = KernelExplainer(model_predict, self.tokenizer.encode(text))
        shap_values = explainer.shap_values(self.tokenizer.encode(text))
        return shap_values

content_filter = ContentFilter()

@app.route('/api/filter/text', methods=['POST'])
async def filter_text():
    data = request.json
    text = data.get('text')
    
    if not text:
        return jsonify({'error': 'No text provided'}), 400
    
    try:
        predictions = content_filter.predict(text)
        explanation = content_filter.explain(text)
        
        return jsonify({
            'predictions': predictions.tolist(),
            'explanation': explanation.tolist(),
            'blocked': predictions[0][1] > 0.913
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
