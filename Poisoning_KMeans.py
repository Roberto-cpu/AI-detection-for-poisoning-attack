import math
import random
import sys

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from copy import deepcopy
from random import randrange
from sklearn.cluster import KMeans
from scipy.spatial import distance


# Questa funzione definisce i centroidi dei cluster
def k_means_cluster(df, na, m, n):
    k = 3  # definisco il numero di cluster

    category = df.values[:, n - 1]

    mean = np.mean(na, axis=0)  # calcolo la media dei valori nel dataset
    std = np.std(na, axis=0)  # calcolo la deviazione standard dei valori nel dataset
    centers = np.random.randn(k, n) * std + mean  # prendo i centroidi randomicamente

    # Rappresento il grafico di dispersione
    colors = ['orange', 'blue', 'green']
    for i in range(m):
        plt.scatter(na[i, 0], na[i, 1], s=7, color=colors[int(category[i])])
    plt.scatter(centers[:, 0], centers[:, 1], marker='*', s=5, color='red')
    plt.show()

    centers_old = np.zeros(centers.shape)
    centers_new = deepcopy(centers)

    na.shape

    clusters = np.zeros(m)
    distances = np.zeros((m, k))

    error = np.linalg.norm(centers_new - centers_old)  # definisco l'errore nel momento in cui i due centri sono uguali

    # Fin quando non si ha l'errore, la ricerca dei centroidi continua
    while error != 0:
        # Misuro la distanza dai centri
        for i in range(k):
            distances[:, i] = np.linalg.norm(na - centers[i], axis=1)

        # Assegno i dati con la distanza più bassa
        clusters = np.argmin(distances, axis=1)

        centers_old = deepcopy(centers_new)
        # Calcolo la media per ogni cluster e aggiorno i centroidi
        for i in range(k):
            centers_new[i] = np.mean(na[clusters == i], axis=0)
        error = np.linalg.norm(centers_new - centers_old)

    print(centers_new)
    return centers_new


# Questa funzione calcola la sigmoide di un elemento
def sigmoid(x):
    return 1 / (1 + math.exp(-x))


# Questa funzione esegue uno xor tra due sequenze binarie
def xor(a, b):
    ans = ""

    print(f'A in xor funct: {a}')

    for i in range(len(b)):
        if int(a[i]) == int(b[i]):
            ans += "0"
        else:
            ans += "1"
        print(f'Ans: {ans}')

    return ans


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

    malware = []
    for var in range(len(numpy_array)):
        if numpy_array[var, permissions_number-1] == 1:
            malware.append(numpy_array[var, range(0, permissions_number - 1)])

    centers = k_means_cluster(dataframe, numpy_array, apks_number, permissions_number)
    i = 0
    tau = 4
    ncluster = 3
    mal_counter = 0                     # inizializzo un contatore per il risultato della predizione

    print(f'malware\n{malware}')

    evaded_samples = []

    file = open("Test_set.arff", "w")
    file.write('@RELATION Android_permissions\n\n')
    for attr in attrs:
        file.write(f'@ATTRIBUTE {attr}\n')
    file.write('\n@DATA\n')
    file.close()

    file = open("Test_set.arff", "a")

    while i < ncluster:
        c = centers[i]
        j = 0
        while j < len(c):
            print(f'C: {c}')
            s = sigmoid(c[j])
            if s > tau:
                c[j] = 1
            else:
                c[j] = 0
            j += 1
        i += 1

    for i in range(len(malware)):
        x = malware[i]
        print(f'i = {i}')
        for j in range(len(centers)):
            print(f'J = {j}')
            c = centers[j]
            print(f'len x: {len(x)}')
            print(f'len c: {len(c)}')
            a = xor(c, x)

            count = 0                              # inizializzo la variabile d'uscita dal while
            while count < ncluster:

                print(f'count = {count}')

                gamma = randrange(len(a))
                k = 0

                print('\n\n')
                print(f'Attempt 0: gamma = {gamma} --> a[gamma] = {a[gamma]}')
                if a[gamma] != '1':
                    while a[gamma] != '1' and k < len(a):
                        print(f'Attempt {k + 1}: gamma = {gamma} --> a[gamma] = {a[gamma]}')
                        gamma = randrange(len(a))
                        k += 1

                print(f'A: {a}')

                predictions = []

                print(f'c = {c}')
                print(f'x = {x}')

                print(f'c[gamma] = {int(c[gamma])} and x[gamma] = {x[gamma]}')

                if int(c[gamma]) == 1 and x[gamma] == 0:
                    x[gamma] = 1            # avveleno il malware

                    print(f'Malware poisoned: {x}')
                    count += 1

                    # Scrivo il malware avvelenato nel test set
                    arr_str = array_to_string(x)
                    appr_form = ""
                    for char in arr_str:
                        appr_form += f'{char}, '
                    file.write(f'{appr_form}?\n')

                    result_df = pd.read_csv('result.csv', sep=',')
                    list_pred = list(result_df.iloc[:, 2])

                    for element in list_pred:
                        elems = element.split(':')
                        elem = elems[1]  # estraggo il risultato della predizione
                        predictions.append(elem)  # aggiungo il risultato nella lista relativa

                    print(f'predictions = {predictions}')
                    print(f'mal_counter = {mal_counter}')
                    print(f'prediction[mal_counter] = {predictions[mal_counter]}')

                    if int(predictions[mal_counter]) == 0:
                        mal_counter += 1
                        count = ncluster + 1
                        evaded_samples.append(x)
                else:
                    break
                    print(f'count = {count}')

    print("\n\nEvaded samples\n")
    for sample in evaded_samples:
        print(f'{sample}')


main()
