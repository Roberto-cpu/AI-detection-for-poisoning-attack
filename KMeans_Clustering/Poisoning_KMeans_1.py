import random

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from random import randrange
from sklearn.cluster import KMeans
from scipy.spatial import distance


def k_means_cluster(df, na, m, n):

    # Con il metodo a gomito verifico il numero di cluster ideali per il mio dataset
    wcss = []
    for i in range(1, m):
        kmeans = KMeans(n_clusters=i, init='k-means++', max_iter=300, n_init=10, random_state=0)
        kmeans.fit(df)
        wcss.append(kmeans.inertia_)
        print('“Cluster”', i, '“Inertia”', kmeans.inertia_)
    plt.plot(range(1, m), wcss)
    plt.title('‘The Elbow Curve’')
    plt.xlabel('‘Number of clusters’')
    plt.ylabel('‘WCSS’')  ##WCSS stands for total within-cluster sum of square
    plt.show()

    # Definisco i centroidi
    kmeans = KMeans(n_clusters=3, init='k-means++', random_state=0)
    kmeans.fit(df)
    centroids = kmeans.cluster_centers_
    print(centroids)

    # rappresento il dataset con un grafico a dispersione
    plt.scatter(df['ACCESS_WIFI_STATE'], df['CLASS'], c=kmeans.labels_.astype(float), s=50, alpha=0.5)
    plt.scatter(centroids[:, 0], centroids[:, 1], c='red', s=50)
    plt.show()

    # definisco le distanze euclidee rispetto i centroidi
    euclideans = []              # inizializzo una lista per le distanze

    # per ogni centroide calcolo la distanza euclidea rispetto tutti gli apk nel dataset
    # le distanze vegono salvate in "euclideans"
    for _ in range(len(centroids)):
        center = centroids[_]
        for index in range(m):
            dist = distance.euclidean(center, na[index])
            euclideans.append(dist)

    print(euclideans)
    print(len(euclideans))

    distances = []
    pos = 0

    for i in range(3):
        dists = []
        for index in range(pos, pos+m):
            pos += 1
            dists.append(euclideans[index])
        distances.append(dists)

    print(distances)


# Questa funzione trasforma un array in una stringa
def array_to_string(array):
    string = str(array)

    string = string.replace(" ", "")
    string = string.replace("[", "")
    string = string.replace("]", "")

    return string


def main():
    # -------------- Dataframe section ---------------------
    dataframe = pd.read_csv("Android_Permissions.csv", sep=";")  # Carico il dataset
    dataframe.drop(dataframe.columns[0], axis=1, inplace=True)  # elimino la prima colonna del dataset

    # Carico in una lista le label delle colonne
    index = dataframe.head(0)
    as_list = list(index)
    # print(as_list)

    # ------------- Numpy Array Section -------------------
    numpy_array = dataframe.values  # creo un numpy array contenente i valori del dataframe
    apks_number = numpy_array.shape[0]  # conto il numero di righe del numpy array
    permissions_number = numpy_array.shape[1]  # conto il numero di colonne del numpy array
    # print(f'Dataset size:\n{numpy_array}')

    # ------------ Preprocessing -------------------------
    """
    Converto il dataset in un file .arff
    """

    attrs = []
    for index in range(0, len(as_list)):
        attrs.append(as_list[index] + ' {0, 1}')

    info = []
    for ind in range(0, apks_number):
        str = " "
        for char in dataframe.iloc[ind]:
            str += f'{char}, '
        info.append(str[:-2])

    with open("Android_Permissions.arff", "w") as dfarff:
        dfarff.write("@RELATION Android_Permissions\n\n")
        for attr in attrs:
            dfarff.write(f"@ATTRIBUTE {attr}\n")
        dfarff.write("\n@DATA\n")
        for inf in info:
            dfarff.write(f'{inf}\n')

    dfarff.close()

    k_means_cluster(dataframe, numpy_array, apks_number, permissions_number)


main()
