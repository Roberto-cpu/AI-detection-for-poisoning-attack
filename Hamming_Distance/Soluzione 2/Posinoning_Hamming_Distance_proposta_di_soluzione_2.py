import linecache
from random import randrange
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from scipy.spatial import distance
import operator
import numpy as np


# Questa funzione trasforma un array in una stringa
def array_to_string(array):
    string = str(array)

    string = string.replace(" ", "")
    string = string.replace("[", "")
    string = string.replace("]", "")

    return string


# Questa funzione esegue uno xor tra due sequenze binarie
def xor(a, b):
    ans = ""

    print(f'A in xor funct: {a}')

    for i in range(len(a)):
        if int(a[i]) == int(b[i]):
            ans += "0"
        else:
            ans += "1"
        print(f'Ans: {ans}')

    return ans


def main():
    # -------------- Dataframe section ---------------------
    dataframe = pd.read_csv("Android_Permissions.csv", sep=";")  # Carico il dataset
    dataframe.drop(dataframe.columns[0], axis=1, inplace=True)  # elimino la prima colonna del dataset

    # Carico in una lista le label delle colonne
    index = dataframe.head(0)
    as_list = list(index)
    print(as_list)

    # ------------- Numpy Array Section -------------------
    numpy_array = dataframe.values  # creo un numpy array contenente i valori del dataframe
    apks_number = numpy_array.shape[0]  # conto il numero di righe del numpy array
    permissions_number = numpy_array.shape[1]  # conto il numero di colonne del numpy array
    print(f'Dataset size: {numpy_array.shape}')

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

    malware = []
    for var in range(len(numpy_array)):
        if numpy_array[var, permissions_number - 1] == 1:
            malware.append(numpy_array[var, range(0, permissions_number - 1)])

    print(f'Malware set --> {malware}')

    # ----------- Pseudo-code implementation -------------
    A = {}  # inizializzo un dizionario contenente la coppia di valori (benign : hamming)
    evaded_samples = []
    delta = 0

    i = 0
    while i < len(malware):
        print(f'I: {i}')
        x = malware[i]  # carico l'i-esima sequenza di bit nella variabile x
        print(f'X[{i}]: {x}\n\n')

        for j in range(apks_number):
            benign = numpy_array[j, 0: permissions_number]  # carico la j-esima sequenza di bit in benign

            if benign[permissions_number - 1] == 0:
                benign = benign[range(0, len(benign) - 1)]
                print(f'Benign without class --> {benign}')
                hamming = xor(x, benign)  # calcolo la distanza di hamming
                hamming = int(hamming, 2)  # eseguo la conversione binario --> decimale
                print(f'Xor result: {hamming}')
                b = array_to_string(benign)  # rendo benign una stringa per usarlo come chiave del dizionario

                if hamming != 0:
                    print(f'Reformat benign: {b}\n\n')
                    A.update({b: hamming})  # carico la coppia (benign : hamming) nel dizionario

        sorted_A = sorted(A.items(), key=operator.itemgetter(1))  # ordino il dizionario per valori ascendenti
        print(f'Sorterd A: {sorted_A}')

        """ Correzione riempimento lista l """
        l = [sorted_A[0][0]]

        for el in range(1, len(sorted_A)):
            if sorted_A[0][1] == sorted_A[el][1]:
                l.append(sorted_A[el][0])

        print(f'L: {l}\n\n')

        j = 0
        while j <= len(l):
            c = 0  # inizializzo il contatore delle feature avvelenate
            benign = l[
                j]  # carico in benign il j-esimo apk benigno con la distanza più corta rispetto l'apk maligno considerato
            numpy_benign = np.array(benign)
            print(f'Benign: {numpy_benign.tolist()}')
            print(f'Malign: {x}\n\n')
            a = xor(benign, x)  # eseguo lo xor tra le due sequenze binarie

            p = 1  # inizializzo p in modo da poter accedere al controllo sulle features

            """
            Per poter gestire il "goto 21" ho preferito implementare un while che continuerà a ciclare fin quando
            la predizione non assumerà valore zero oppure la perturbazione non assumerà un valore superiore a "delta".
            Fin quando una di queste due condizioni non si verifica, verrà selezionato una nuova feature, casualmente scelta, dei due apk
            """
            while int(p) != 0 and c <= delta:
                gamma = randrange(len(a))
                k = 0

                print('\n\n')
                print(f'Attempt 0: gamma = {gamma} --> a[gamma] = {a[gamma]}')
                if a[gamma] != '1':
                    while a[gamma] != '1' and k < len(a):
                        print(f'Attempt {k + 1}: gamma = {gamma} --> a[gamma] = {a[gamma]}')
                        gamma = randrange(len(a))
                        k += 1

                print(f'a[{gamma}] at the end of the while loop: {a[gamma]}')

                if a[gamma] == 0:
                    j += 1
                    continue

                print('\n\n')

                print(f'benign[gamma] = {benign[gamma]}')
                print(f'x[gamma] = {x[gamma]}')

                predictions = []
                if int(benign[gamma]) == 1 and int(x[gamma]) == 0:
                    x[
                        gamma] = 1  # Se solo l'applicativo benigno ha il permesso considerato, impongo il permesso anche all'apk maligno
                    c += 1
                    print(f'poisoned x = {x}')
                    malware[i] = x  # sostituisco il malware avvelenato a quello originale
                    print(malware)

                    """
                    Creo un file arff contenente il test set
                    """

                    data_s = []

                    for index_data in range(0, len(malware)):
                        str = ""
                        for char in malware[index_data]:
                            str += f'{char}, '
                        str += '?'
                        data_s.append(str)

                    print(f'Datas: {data_s}')

                    with open("Test_set.arff", "w") as file:
                        file.write('@RELATION Android_permissions\n\n')
                        for attr in attrs:
                            file.write(f'@ATTRIBUTE {attr}\n')
                        file.write('\n@DATA\n')
                        for data in data_s:
                            file.write(f' {data}\n')

                p = 0

            if p == 0:
                i += 1
                evaded_samples.append(x)
                break
            else:
                i += 1
                break

    print('\n\nEvaded Samples:')
    for i in evaded_samples:
        print(f'{i}')
"""                  
                        Terminata la produzione del file .arff contenente il test set, viene eseguita, mediante
                        Weka, la classificazione dei malware e la predizione della loro classe.
                        Il risultato è stato salvato in un file .txt e successivamente aperto nell'implementazione
                    
                    file = open("result.txt", 'r')
                    int_lines = []                  # inizializzo una lista contenente le righe del file utili
                    num_line = 0                    # inizializzo una variabile contenente il numero totale di righe nel file
                    int_pos = 0                     # inizializzo una variabile contenente la riga da cui parte la predizione
                    lines = []                      # inizializzo una lista contenente le righe del file

                    # Conto le righe del file
                    for line in file:
                        num_line += 1
                        # verifico a quale riga è presente la seguente stringa
                        if "inst#,actual,predicted,error,prediction" in line:
                            int_pos = num_line
                        lines.append(line)
                        print(f'Linea{num_line}: {line}')

                    file.close()                # chiudo il file

                    # Stampe di debug
                    print(f'Numero linee: {num_line}')
                    print(f'Linea interessata: {int_pos}')
                    print(lines)

                    # Carico in una lista le righe riportanti il risultato della predizione (escludendo il \n)
                    for index in range(int_pos, (int_pos+len(malware))):
                        int_lines.append(lines[index][:-1])

                    # Divido le singole stringe al fine di ottenere il solo risultato della predizione
                    for res in int_lines:
                        results = res.split(",")[2]
                        predictions.append(results.split(":")[1])

                    print(predictions)

                if len(predictions) != 0:
                    p = predictions[i]
                else:
                    p = 0

            
                - se l'uscita è dovuta ad una predizione con valore 0, il malware verrà aggiungo alla lista di malware evasi e ne verrà processato un altro
                - se l'uscita è dovuta al valore della perturbazione (c > delta), il malware verrà considerato non evasco e si passerà al malware successivo
            
            if p == 0:
                i += 1
                evaded_samples.append(x)
                break
            else:
                i += 1
                break

    print('\n\nEvaded Samples:')
    for i in evaded_samples:
        print(f'{i}')
"""

main()
