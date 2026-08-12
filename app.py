"""
Flask Web Application for Suspicious Link Analyzer
Provides a web interface for URL security analysis
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
from predict import URLPredictor

# QR Scanner imports
import io
import re
import sys
import site

# Ensure user site-packages is on sys.path so pyzbar/pillow/numpy are found
# regardless of whether Flask is launched from system Python or a venv
for _sp in site.getusersitepackages() if isinstance(site.getusersitepackages(), list) else [site.getusersitepackages()]:
    if _sp not in sys.path:
        sys.path.insert(0, _sp)

try:
    from PIL import Image
    import numpy as np
    from pyzbar.pyzbar import decode as qr_decode
    QR_AVAILABLE = True
    print("✅ QR scanning libraries loaded successfully")
except ImportError as _e:
    QR_AVAILABLE = False
    print(f"⚠️  QR scanning libraries not available: {_e}")

app = Flask(__name__)
CORS(app)

predictor = None

def initialize_predictor():
    """Initialize the URL predictor"""
    global predictor
    
    model_path = 'url_classifier_model.pkl'
    
    if not os.path.exists(model_path):
        print("⚠️  No trained model found. Training new model...")
        from train_model import URLModelTrainer
        from dataset_loader import DatasetLoader
        
        loader = DatasetLoader()
        df = loader.load_dataset()
        
        trainer = URLModelTrainer()
        X, y = trainer.prepare_data(df)
        trainer.train(X, y)
        trainer.save_model()
        
        print("✅ Model training complete!")
    
    predictor = URLPredictor()
    print("✅ Predictor initialized and ready!")

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """
    API endpoint to analyze a URL
    Expects JSON: {"url": "http://example.com"}
    Returns JSON with analysis results
    """
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'error': 'No URL provided'
            }), 400
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        result = predictor.predict(url)
        
        if result[0] is None:
            return jsonify({
                'error': 'Model not loaded'
            }), 500
        
        prediction, probability, explanation, features = result
        
        is_malicious = prediction == 1
        confidence = probability[1] if is_malicious else probability[0]
        
        response = {
            'url': url,
            'verdict': 'suspicious' if is_malicious else 'safe',
            'confidence': float(confidence),
            'reasons': explanation if is_malicious else [],
            'features': {
                'url_length': int(features['url_length']),
                'has_https': bool(features['has_https']),
                'has_ip': bool(features['has_ip']),
                'suspicious_keywords': int(features['num_suspicious_keywords']),
                'num_dots': int(features['num_dots']),
                'num_hyphens': int(features['num_hyphens'])
            }
        }
        
        return jsonify(response)
    
    except Exception as e:
        print(f"Error analyzing URL: {str(e)}")
        return jsonify({
            'error': f'Analysis failed: {str(e)}'
        }), 500

@app.route('/api/batch-analyze', methods=['POST'])
def batch_analyze():
    """
    API endpoint to analyze multiple URLs
    Expects JSON: {"urls": ["url1", "url2", ...]}
    Returns JSON with batch analysis results
    """
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls:
            return jsonify({
                'error': 'No URLs provided'
            }), 400
        
        results = []
        for url in urls:
            url = url.strip()
            if not url:
                continue
                
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            try:
                result = predictor.predict(url)
                prediction, probability, explanation, features = result
                
                is_malicious = prediction == 1
                confidence = probability[1] if is_malicious else probability[0]
                
                results.append({
                    'url': url,
                    'verdict': 'suspicious' if is_malicious else 'safe',
                    'confidence': float(confidence)
                })
            except Exception as e:
                results.append({
                    'url': url,
                    'verdict': 'error',
                    'error': str(e)
                })
        
        safe_count = sum(1 for r in results if r['verdict'] == 'safe')
        suspicious_count = sum(1 for r in results if r['verdict'] == 'suspicious')
        
        return jsonify({
            'results': results,
            'summary': {
                'total': len(results),
                'safe': safe_count,
                'suspicious': suspicious_count
            }
        })
    
    except Exception as e:
        print(f"Error in batch analysis: {str(e)}")
        return jsonify({
            'error': f'Batch analysis failed: {str(e)}'
        }), 500

@app.route('/api/model-info', methods=['GET'])
def model_info():
    """Get information about the trained model"""
    try:
        model_path = 'url_classifier_model.pkl'
        
        if not os.path.exists(model_path):
            return jsonify({
                'status': 'not_trained',
                'message': 'No trained model found'
            })
        
        size_bytes = os.path.getsize(model_path)
        size_mb = size_bytes / (1024 * 1024)
        
        return jsonify({
            'status': 'ready',
            'model_file': model_path,
            'model_size_mb': round(size_mb, 2),
            'model_type': 'RandomForest Classifier',
            'features_count': 21,
            'algorithm': 'Ensemble Learning'
        })
    
    except Exception as e:
        return jsonify({
            'error': f'Failed to get model info: {str(e)}'
        }), 500

@app.route('/api/scan-qr', methods=['POST'])
def scan_qr():
    """
    QR Scanner endpoint: accepts an uploaded image, decodes the QR code,
    and returns the extracted URL (or text) without running URL analysis.
    The frontend then calls /api/analyze with the extracted URL.
    """
    if not QR_AVAILABLE:
        return jsonify({'error': 'QR scanning libraries not available on this server.'}), 503

    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided.'}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No file selected.'}), 400

    # Validate file extension
    allowed_ext = {'png', 'jpg', 'jpeg'}
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in allowed_ext:
        return jsonify({'error': 'Invalid file type. Please upload PNG, JPG, or JPEG.'}), 400

    try:
        # Read image bytes and open with Pillow
        img_bytes = file.read()
        image = Image.open(io.BytesIO(img_bytes)).convert('RGB')
        img_array = np.array(image)

        # Decode QR codes from the image
        decoded_objects = qr_decode(img_array)

        if not decoded_objects:
            return jsonify({'error': 'No QR code detected in the image.'}), 422

        # Use the first detected QR code
        raw_data = decoded_objects[0].data.decode('utf-8', errors='replace').strip()

        if not raw_data:
            return jsonify({'error': 'QR code is empty or unreadable.'}), 422

        # Check if the QR content is a URL
        url_pattern = re.compile(
            r'^(https?://|www\.)[^\s]{2,}', re.IGNORECASE
        )
        is_url = bool(url_pattern.match(raw_data))

        return jsonify({
            'qr_content': raw_data,
            'is_url': is_url
        })

    except Exception as e:
        print(f"QR decode error: {str(e)}")
        return jsonify({'error': f'QR decoding failed: {str(e)}'}), 500


if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔒 SUSPICIOUS LINK ANALYZER - WEB APPLICATION")
    print("="*60)
    print("\n🚀 Starting web server...")
    
    initialize_predictor()
    
    print("\n✅ Server ready!")
    print("🌐 Access the app at: http://0.0.0.0:5000")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
