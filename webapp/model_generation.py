import tensorflow as tf
from tensorflow import keras
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense, Input

# 🟢 Step 1: Load Dataset and Remove Unnecessary Columns
urldata = pd.read_csv("./Url_Processed.csv")

# Drop unnecessary columns
urldata.drop("Unnamed: 0", axis=1, inplace=True)
urldata.drop(["url", "label"], axis=1, inplace=True)

# 🟢 Step 2: Feature Selection
x = urldata[['hostname_length', 'path_length', 'fd_length', 'count-', 'count@', 'count?',
             'count%', 'count.', 'count=', 'count-http', 'count-https', 'count-www',
             'count-digits', 'count-letters', 'count_dir', 'use_of_ip']]
y = urldata['result']

# 🟢 Step 3: Balance Dataset using SMOTE
x_sample, y_sample = SMOTE().fit_resample(x, y.values.ravel())

# Convert to DataFrame
x_sample = pd.DataFrame(x_sample)
y_sample = pd.DataFrame(y_sample)

# 🟢 Step 4: Train-Test Split (80:20)
x_train, x_test, y_train, y_test = train_test_split(x_sample, y_sample, test_size=0.2, random_state=42)

# 🟢 Step 5: Define MLP Model (Fixed Warning: Using `Input` Layer)
model = Sequential([
    Input(shape=(16,)), 
    Dense(32, activation='relu'),
    Dense(16, activation='relu'),
    Dense(8, activation='relu'),
    Dense(1, activation='sigmoid')  # Output Layer for Binary Classification
])

model.summary()

# 🟢 Step 6: Define Optimizer and Compile Model
opt = keras.optimizers.Adam(learning_rate=0.001)  # Explicit learning_rate
model.compile(optimizer=opt, loss='binary_crossentropy', metrics=['accuracy'])

# 🟢 Step 7: Define Callback to Stop Early if Validation Loss < 0.1
class ModelCallback(keras.callbacks.Callback):
    def on_epoch_end(self, epoch, logs=None):
        if logs.get('val_loss') < 0.1:
            print("\nReached 0.1 val_loss! Stopping training!")
            self.model.stop_training = True

callback = ModelCallback()

# 🟢 Step 8: Train Model
history = model.fit(x_train, y_train, epochs=10, batch_size=256, 
                    callbacks=[callback], validation_data=(x_test, y_test), verbose=1)

# 🟢 Step 9: Save Model (Fixed Warning: Ensure Optimizer State is Saved)
model.save("Malicious_URL_Prediction.h5", save_format="h5")

# 🟢 Step 10: Predict on Test Set
pred_test = model.predict(x_test)

# Convert predictions to binary labels
pred_test = (pred_test >= 0.5).astype(int)

def view_result(array):
    """Helper function to print classification results."""
    for i in array.flatten():
        print("Malicious" if i == 1 else "Safe")

# Display Predicted vs. Actual Results (First 10 Samples)
print("PREDICTED RESULTS:")
view_result(pred_test[:10])

print("\nACTUAL RESULTS:")
view_result(y_test[:10].values)

# 🟢 Step 11: Reload and Use the Model (Fixes Warning: Recompile after Loading)
model_loaded = load_model("Malicious_URL_Prediction.h5", compile=False)
model_loaded.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Verify Model Works After Loading
sample_prediction = model_loaded.predict(x_test[:5])
sample_prediction = (sample_prediction >= 0.5).astype(int)
print("\nLOADED MODEL SAMPLE PREDICTIONS:")
view_result(sample_prediction)
