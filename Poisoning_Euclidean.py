import pandas as pd
from random import randrange
from scipy.spatial import distance
from sklearn import svm
from sklearn.model_selection import train_test_split
import numpy as np


# Questa funzione trasforma un array in una stringa
def array_to_string(array):
    string = str(array)

    string = string.replace(" ", "")
    string = string.replace("[", "")
    string = string.replace("]", "")

    return string


# Questa funzione esegue il check sulla classificazione
def check(f):
    predictions = []
    ecount = 0
    if f == 0:  # se il flag è 0 aggiorno p
        # leggo il csv contenente il risultato
        result_df = pd.read_csv("result.csv", sep=",")
        list_pred = list(result_df.iloc[:, 2])

        for element in list_pred:
            elems = element.split(':')
            elem = elems[1]  # estraggo il risultato della predizione
            predictions.append(elem)  # aggiungo il risultato nella lista relativa

    for p in range(len(predictions)):
        if int(predictions[p]) == 0:
            ecount += 1

    return ecount


def main():
    # Mediante il modulo padas, carico il dataset
    dataframe = pd.read_csv("Android_Permissions.csv", sep=";")
    # Elimino la prima colonna del dataframe
    dataframe.drop(dataframe.columns[0], axis=1, inplace=True)

    # Carico in una lista le label delle colonne
    index = dataframe.head(0)
    as_list = list(index)
    print(as_list)

    # Carico in una lista i nomi della applicazioni
    apk_names = dataframe.iloc[:, 0]
    apk_list = list(apk_names)
    print(apk_list)

    # Converto il dataset in un file .arff
    attrs = [as_list[0] + ' numeric']
    for index in range(1, len(as_list)):
        attrs.append(as_list[index] + ' {0, 1}')

    info = []
    for ind in range(0, len(apk_list)):
        strs = " "
        for char in dataframe.iloc[ind]:
            strs += f'{char}, '
        info.append(strs[:-2])

    with open("Android_Permissions.arff", "w") as dfarff:
        dfarff.write("@RELATION Android_Permissions\n\n")
        for attr in attrs:
            dfarff.write(f"@ATTRIBUTE {attr}\n")
        dfarff.write("\n@DATA\n")
        for inf in info:
            dfarff.write(f'{inf}\n')

    # Creo un numpy_array contenente i soli valori presenti nel dataframe
    numpy_array = dataframe.values

    # Calcolo il numero di righe, colonne e la dimensione totale del dataframe
    apks_num = numpy_array.shape[0]
    permissions_num = numpy_array.shape[1]
    dataframe_size = apks_num * permissions_num

    # Inizializzo due array che andranno a contenere le app maligne e benigne
    malware = []
    benign = []

    file = open("Test_set.arff", "w")
    file.write('@RELATION Android_permissions\n\n')
    for attr in attrs:
        file.write(f'@ATTRIBUTE {attr}\n')
    file.write('\n@DATA\n')
    file.close()

    file = open("Test_set.arff", "a")

    # Riempio gli array imponendo come benigne le app di classe '0' e come maligne le app di classe '1'
    for i in range(apks_num):
        if numpy_array[i, permissions_num - 1] == 1:
            malware.append(numpy_array[i, range(0, permissions_num - 1)])
        else:
            benign.append(numpy_array[i, range(0, permissions_num - 1)])

    delta = 1
    edist = []
    sample = []
    evasion_count = 0
    samples = []
    sum_dist = 0
    flag = 1

    for k in range(len(malware)):  # eseguo un loop sul numero di malware presenti nella lista
        count = 0  # Nel caso in cui si voglia contare il numero avvelenamenti
        print(f'K: {k}')
        for i in range(len(benign)):  # eseguo un loop sul numero di apk benigni presenti nella lista
            r = 0  # inizializzo la perturbazione
            avg = 0  # inizializzo la media delle distanze
            m = 0  # inizializzo un contatore d'uscita dal while
            while r <= delta and m < apks_num:
                print(f'APKS_num: {apks_num}    M: {m}')
                m += 1
                sample = malware[k]  # carico in sample il k-esimo malware
                controller = benign[i]  # carico in controller l'm-esimo apk benigno
                r_num = randrange(len(sample))
                # verifico la condizione su delle feature casuali
                if controller[r_num] == 1 and sample[r_num] == 0:
                    count += 1  # incremento il conteggio di avvelenamenti
                    sample[r_num] = 1  # forzo il permesso
                    samples.append(sample)
                    arr_str = array_to_string(sample)
                    appr_form = ""
                    for char in arr_str:
                        appr_form += f'{char}, '
                    file.write(f'{appr_form}?\n')
                    r += 1  # incremento la perturbazione
                    dist = 0
                    sum_dist = 0
                    print(f'R: {r}')

                    for j in range(len(benign)):
                        dist = distance.euclidean(sample, benign[
                            j])  # calcolo la distanza euclidea tra il sample ed il j-esimo apk benigno
                        print(f'Dist: {dist}')
                        edist.append(dist)
                        sum_dist += dist

                    avg = sum_dist / len(benign)
                    edist.sort()
                    for h in edist:
                        print(f'Edist: {h}')

                    for l in range(len(benign) * delta):
                        print(f'Edist length: {len(edist)} and L: {l}')
                        print(f'Average: {avg}')
                        if avg < edist[l]:  # verifico che la media sia minore dell'l-esima distanza euclidea
                            flag = 0  # in caso positico impongo il flag a 0
                    print(f'Flag: {flag}')

                    evasion_count = check(flag)

        evasion_count = check(flag)

    print("Evasion count: ", evasion_count)


main()
