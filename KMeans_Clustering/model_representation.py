import matplotlib.pyplot as plt
import pandas as pd

data = pd.read_csv("Android_Permissions.csv", sep=";")
print (data.head())

color = ["red", "blue", "green"]

X = data[["ACCESS_WIFI_STATE", "ACCESS_NETWORK_STATE", "BLUETOOTH", "WRITE_EXTERNAL_STORAGE", "CLASS"]]

plt.scatter(X["CLASS"], X["ACCESS_WIFI_STATE"], X["ACCESS_NETWORK_STATE"], X["BLUETOOTH"], X["WRITE_EXTERNAL_STORAGE"], c= color[k])
plt.xlabel("CLASS")
plt.ylabel("ACCESS_WIFI_STATE")
plt.show()