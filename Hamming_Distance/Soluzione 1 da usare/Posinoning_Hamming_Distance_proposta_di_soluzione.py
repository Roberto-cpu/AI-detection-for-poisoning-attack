import sys
from random import randrange
import pandas as pd
import operator
import numpy as np


# Questa funzione trasforma un array in una stringa
def array_to_string(array):
    string = str(array)

    string = string.replace(" ", "")
    string = string.replace("[", "")
    string = string.replace("]", "")

    # Impongo la virgola dopo ogni valore, in modo da poter forzare lo split
    new_string = string[0]
    for char_pos in range(1, len(string)):
        new_string += f', {string[char_pos]}'

    # print(f'Debug: {new_string}')  # STAMPA DI DEBUG
    return new_string


# Questa funzione esegue uno xor tra due sequenze binarie
def xor(a, b):
    ans = ""
    # print(f'len a = {len(a)}')
    # print(f'A in xor funct: {a}')

    if a is None:
        print("L'array è null")

    # print(f'Debug {a.shape}')

    for i in range(len(a)):
        # print(f'A[{i}] = {a[i]}')
        # print(f'B[{i}] = {b[i]}')
        if int(a[i]) == int(b[i]):
            ans += "0"
        else:
            ans += "1"

    return ans


def main():
    # -------------- Dataframe section ---------------------
    dataframe = pd.read_csv("data_2000apk.csv", sep=";")  # Carico il dataset
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

    # Converto il dataset in un file .arff
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
    test_set = np.array([])
    for var in range(len(numpy_array)):
        if numpy_array[var, permissions_number - 1] == 1:
            malware.append(numpy_array[var, range(0, permissions_number - 1)])

    print(f'Malware set --> {malware}')

    # ----------- Pseudo-code implementation -------------
    A = {}  # inizializzo un dizionario contenente la coppia di valori (benign : hamming)
    evaded_samples = []
    delta = 4
    file = open("Test_set.arff", "w")
    flag = 0

    file.write('@RELATION Android_permissions\n\n')
    for attr in attrs:
        file.write(f'@ATTRIBUTE {attr}\n')
    file.write('\n@DATA\n')
    file.close()

    file = open("Test_set.arff", 'a')

    i = 0
    while i < len(malware):
        print(f'I: {i}')
        np.set_printoptions(threshold=np.inf)
        x = malware[i]  # carico l'i-esima sequenza di bit nella variabile x
        print(f'X[{i}]: {x}\n\n')

        for j in range(apks_number):
            benign = numpy_array[j, 0: permissions_number]  # carico la j-esima sequenza di bit in benign
            np.set_printoptions(threshold=np.inf)

            if benign[permissions_number - 1] == 0:
                benign = benign[range(0, len(benign) - 1)]
                # print(f'Benign without class --> {benign}')
                hamming = xor(x, benign)  # calcolo la distanza di hamming
                hamming = int(hamming, 2)  # eseguo la conversione binario --> decimale
                # print(f'Xor result: {hamming}')
                b = array_to_string(benign)  # rendo benign una stringa per usarlo come chiave del dizionario

                if hamming != 0:
                    # print(f'Reformat benign: {b}\n\n')
                    A.update({b: hamming})  # carico la coppia (benign : hamming) nel dizionario

        sorted_A = sorted(A.items(), key=operator.itemgetter(1))  # ordino il dizionario per valori ascendenti
        # print(f'Sorterd A: {sorted_A}')

        """ Correzione riempimento lista l """
        l = [sorted_A[0][0]]

        for el in range(1, len(sorted_A)):
            if sorted_A[0][1] == sorted_A[el][1]:
                l.append(sorted_A[el][0])

        # raccolgo in new_l le liste di permessi
        new_l = []
        for element in l:
            int_el = element.split(", ")
            int_l = []
            for el_pos in range(len(int_el)):
                if int_el[el_pos] == "\n":
                    continue
                int_l.append(int(int_el[el_pos]))
            new_l.append(int_l)

        # print(f'L: {new_l}')  # STAMPA DI DEBUG

        j = 0
        while j < len(new_l):
            # print(f'l[j] = {new_l[j]}')
            c = 0  # inizializzo il contatore delle feature avvelenate
            benign = np.array(new_l[
                                  j])  # carico in benign il j-esimo apk benigno con la distanza più corta rispetto l'apk maligno considerato
            np.set_printoptions(threshold=np.inf)

            # print(f'Benign: {benign}\n')
            # print(f'Malign: {x}\n\n')

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

                # print('\n\n')
                # print(f'Attempt 0: gamma = {gamma} --> a[gamma] = {a[gamma]}')
                if a[gamma] != '1':
                    random_check = []
                    while a[gamma] != '1' and k < len(a):
                        # print(f'Attempt {k + 1}: gamma = {gamma} --> a[gamma] = {a[gamma]}')
                        gamma = randrange(len(a))
                        if gamma in random_check:
                            continue
                        random_check.append(gamma)
                        k += 1

                # print(f'a[{gamma}] at the end of the while loop: {a[gamma]}')
                # print('\n\n')

                # print(f'benign[gamma] = {benign[gamma]}')
                # print(f'x[gamma] = {x[gamma]}')

                predictions = []

                c += 1
                # print(f'CCCCCCCCCCCCCCCC {c}')
                if int(benign[gamma]) == 1 and int(x[gamma]) == 0 and int(a[gamma]) == 1:
                    x[
                        gamma] = 1  # Se solo l'applicativo benigno ha il permesso considerato, impongo il permesso anche all'apk maligno

                    # print(f'poisoned x = {x}')

                    # if malware[i].tolist() in test_set.tolist():
                    #     sys.exit()

                    #if malware[i].tolist() not in test_set.tolist():

                        # arr_str = f'{x[0]}'
                        # for element in x:
                        #     arr_str += f', {element}'
                        # print(f'arr_str = {arr_str}, ?')

                        # appr_form = ""
                        # for char in arr_str:
                        # appr_form += f'{char}, '
                        # appr_form = appr_form.replace(", ,,  ", "")
                        # print(f'appr_form = {appr_form}')
                        # file.write(f'{arr_str}, ?\n')
                        # test_set = np.append(test_set, malware[i], axis=0)
                        # print(f'Test set: {len(test_set)}')
                    # leggo il csv contenente il risultato
                    result_df = pd.read_csv("result_RF.csv", sep=",")
                    list_pred = list(result_df.iloc[:, 2])
                    for element in list_pred:
                        elems = element.split(':')
                        elem = elems[1]  # estraggo il risultato della predizione
                        predictions.append(elem)  # aggiungo il risultato nella lista relativa
                    # print("RESULT DF: ", predictions)

                # print(len(predictions))
                # se il file non è stato letto vuol dire che non c'è stato avvelenamento
                # di conseguenza il malware non viene compreso nella predizione
                # nel momento in cui il file viene letto viene verificata la relativa predizione
                if len(predictions) != 0 and flag < len(predictions):
                   print(f'flag = {flag}')
                   p = predictions[flag]
                   flag += 1
                   print(flag, " ", p)
                else:
                    p = 1

                """ Verifico p:
                    - se p = 0 aggiungo il malware alla lista di malware evasi e passo a quello successivo
                    - se p = 1 il malware non è evaso e passo a quello successivo """
                if int(p) == 0:
                    i += 1
                    evaded_samples.append(x)
                    print(f'Ev samples: {evaded_samples}')  # stampa di debug per verificare il corretto  riempimento della lista
                    break
                else:
                    i += 1
                    j = len(new_l)
                    break

    # stampo la lista di malware evasi
    print('\n\nEvaded Samples:')
    for i in evaded_samples:
        print(f'{i}')
    print(len(evaded_samples))


main()
