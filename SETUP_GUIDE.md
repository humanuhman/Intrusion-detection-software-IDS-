# Quick Setup Guide for VS Code

## 📦 Installation & Setup

### Step 1: Extract the Project
```bash
# Unzip the file
unzip ids_project.zip
cd ids_project
```

### Step 2: Create Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate

# On Mac/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

**Required packages:**
- numpy
- pandas
- scikit-learn
- matplotlib
- seaborn
- flask
- joblib

### Step 4: Verify Installation
```bash
cd src
python example.py
```

If you see the demo running successfully, you're all set! 🎉

---

## 🚀 Running the Project

### Option 1: Simple Demo
```bash
cd src
python example.py
```
This runs three quick demos showing packet detection capabilities.

### Option 2: Real-time Monitoring (CLI)
```bash
cd src
python realtime_detection.py
```
This shows live packet analysis with alerts in the terminal.

### Option 3: Web Dashboard
```bash
cd src
python web_dashboard.py
```
Then open your browser to: **http://127.0.0.1:5000**

---

## 🔧 VS Code Tips

### Recommended Extensions
- Python (Microsoft)
- Pylance
- Python Debugger

### Open the Project
1. Open VS Code
2. File → Open Folder → Select `ids_project`
3. VS Code will detect the Python environment

### Running Scripts in VS Code
- Open any `.py` file
- Press `F5` to run with debugger
- Or click the ▶️ play button in the top right

### Terminal in VS Code
- View → Terminal (or Ctrl+`)
- Make sure virtual environment is activated
- Run any commands from there

---

## 📁 Project Structure Quick Reference

```
ids_project/
├── src/
│   ├── data_loader.py          # Data generation
│   ├── train_model.py          # Model training
│   ├── realtime_detection.py  # Detection engine
│   ├── web_dashboard.py        # Web interface
│   └── example.py              # Demo scripts ⭐ START HERE
├── models/                      # Pre-trained models
├── visualizations/              # Performance charts
├── README.md                    # Full documentation
└── PROJECT_SUMMARY.md          # Project overview
```

---

## 🎯 Quick Commands Cheatsheet

```bash
# Run simple demo
cd src && python example.py

# Train new model (if needed)
cd src && python train_model.py

# Start real-time monitoring
cd src && python realtime_detection.py

# Launch web dashboard
cd src && python web_dashboard.py

# Install dependencies
pip install -r requirements.txt

# Check Python version (need 3.8+)
python --version
```

---

## 🐛 Troubleshooting

**"Module not found" error:**
```bash
pip install -r requirements.txt
```

**"Model file not found":**
Make sure you're in the `src` directory when running scripts, or the models are in `../models/`

**Port 5000 already in use (web dashboard):**
```bash
# Kill existing process on port 5000
# Windows:
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Mac/Linux:
lsof -ti:5000 | xargs kill -9
```

**Import errors in VS Code:**
- Make sure you selected the correct Python interpreter
- Press `Ctrl+Shift+P` → "Python: Select Interpreter"
- Choose the one in your `venv` folder

---

## 📚 Next Steps

1. ✅ Run `example.py` to see it in action
2. 📖 Read `README.md` for detailed documentation
3. 🎨 Try the web dashboard
4. 🔧 Modify parameters in the code
5. 🧪 Train with different data sizes
6. 🚀 Extend with your own features!

---

## 💡 Usage Examples

**Detect a single packet:**
```python
from realtime_detection import RealTimeIDS

ids = RealTimeIDS()

packet = {
    'duration': 0.5,
    'protocol_type': 'tcp',
    'service': 'http',
    # ... other features
}

result = ids.detect(packet)
print(f"Attack: {result['is_attack']}")
```

**Monitor traffic stream:**
```python
from realtime_detection import RealTimeIDS, generate_sample_traffic

ids = RealTimeIDS()
traffic = generate_sample_traffic(n_packets=100)

ids.monitor_traffic(traffic, duration=60)
```

---

## 🎓 Learning Resources

- **README.md** - Complete project documentation
- **PROJECT_SUMMARY.md** - Overview and achievements
- **src/example.py** - Working code examples
- All source files have detailed comments!

---

**Need Help?** Check the main README.md file for comprehensive documentation.

**Happy Coding! 🚀**
