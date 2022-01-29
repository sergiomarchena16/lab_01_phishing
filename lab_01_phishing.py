
# Lab 01 - Deteccion de Phishing
# SERGIO MARCHENA - 16387
# SECURITY DATA SCIENCE

from random import random
import pandas as pd
import numpy as np
from sklearn import metrics, model_selection, tree
import  matplotlib.pyplot as plt
import pandas_profiling as pp
from pandas_profiling import ProfileReport

# PARTE 1

# EXPLORACION DE DATOS
print("PARTE 1 COMENZADA")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

df = pd.read_csv("C:\\Users\\sergi\\Desktop\\UVG\\2022\\SECURITY DATA SCIENCE\\lab_01_phishing\\lab_01_phishing\\dataset_pishing.csv", encoding="utf-8")

df['status'].value_counts(dropna=False)

# El dataset esta balanceado exactamente en 50/50, es decir, el 50% de las observaciones esta categorizada como phishing y el otro 50% esta clasificado como legitimate

# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# DERIVACION DE CARACTERISTICAS
## Derivacion de: f1, f2: URL parts lengths

# f1: full url length
df['f1'] = df['url'].str.len()
df[['url','f1']]

# f2: hostname length
# funcion para separar hostname de url:
from urllib.parse import urlparse
def get_domain(url):
  o = urlparse(url)
  return o.hostname

df['hostname'] = df['url'].apply(get_domain)
df['f2'] = df['hostname'].str.len()

df[['url','f1', 'f2', 'hostname']]

# Derivacion de: f4-f20: Caracteres especiales en 'url'

# f4: (.)
df['f4'] = df['url'].str.count('\\.')
df[['url', 'f4']]

# f5: (-)
df['f5'] = df['url'].str.count('-')
df[['url','f5']]

# f6: (@)
df['f6'] = df['url'].str.count('@')
df[['url', 'f6']]

# f7: (?)
df['f7'] = df['url'].str.count('\\?')
df[['url','f7']]

# f8: (&)
df['f8'] = df['url'].str.count('&')
df[['url','f8']]

# f9: (|)
df['f9'] = df['url'].str.count('\\|')
df[['url','f9']]

# f10: (=)
df['f10'] = df['url'].str.count('=')
df[['url','f10']]

# f11: (_)
df['f11'] = df['url'].str.count('_')
df[['url','f11']]

# f12: (Â¯)
df['f12'] = df['url'].str.count('Â¯')
df[['url','f12']]

# f13: (%)
df['f13'] = df['url'].str.count('%')
df[['url','f13']]

# f14: (/)
df['f14'] = df['url'].str.count('/')
df[['url','f14']]

# f15: (*)
df['f15'] = df['url'].str.count('\\*')
df[['url','f15',]]

# f16: (:)
df['f16'] = df['url'].str.count('\\:')
df[['url','f16',]]

# f17: (,)
df['f17'] = df['url'].str.count('\\,')
df[['url','f17']]

# f18: (;)
df['f18'] = df['url'].str.count('\\;')
df[['url','f18',]]

# f19: ($)
df['f19'] = df['url'].str.count('\\$')
df[['url','f19',]]

# f20: (space)
df['f20'] = df['url'].str.count('\s')
df[['url','f20',]]

df.drop(['hostname'], axis=1, inplace=True)
df

# f25: HTTPS indicator
df['f255'] = df['url'].str.startswith('https')
df['f25'] = np.multiply(df['f255'],1)
df['f25'] = np.multiply(df['f255'],1)
df.drop(['f255'], axis=1, inplace=True)
df[['url','f25']]

# f26: Digits ratio in 'url'
def digitsRatio(x):
  digits = sum(c.isdigit() for c in x)
  length = len(x)
  try:
    proporcion = digits/length
  except:
      proporcion = 0
  return proporcion

df['f26'] = df['url'].apply(digitsRatio)
df[['url','f26']]

# f27: Digits raio in 'hostname'
df['hostname'] = df['url'].apply(get_domain)
df['f27'] = df['hostname'].apply(digitsRatio)
df[['hostname','f27']]

df.drop(['hostname'],axis=1,inplace=True)
df['hostname'] = df['url'].apply(get_domain)
df.head()
print("PARTE 1 : DERIVACION DE CARACTERISTICAS TERMINADO")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# PREPROCESAMIENTO

# Codificacion de la variable objetivo: 'status'
def changeStatus(x):
  if (x =='phishing'):
    x = x.replace('phishing', '1')
    return x
  elif (x == 'legitimate'):
    x = x.replace('legitimate', '0')
    return x

df['status'] = df['status'].apply(changeStatus)

# verificacion y eliminacion de columna 'hostname'
df.drop(['hostname'], axis=1, inplace=True)

# eliminacion del dominio
df.drop('url', axis=1, inplace=True)
dfTest = df
df.head()
dfTest.head()
print("PARTE 1 : PREPROCESAMIENTO TERMINADO")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# VISUALIZACION DE RESULTADOS

# Features finales

df = df.apply(pd.to_numeric)
#df = df.astype(int)

df_final = df
finalFeatures = df_final.columns
print('final features:' , finalFeatures)
print("PARTE 1 : VISUALIZACION DE RESULTADOS TERMINADA")
print("(ver archivo html para ver los resultados)")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")


# Reporte
#profile = ProfileReport(df)
#profile.to_file('Reporte de data de PhishingNUEVONUEVO.html')

# print(pd.__version__)
#!pip freeze |grep pandas-profiling


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# SELECCION DE CARACTERISTICAS

# Eliminacion de columnas constantes e irrelevantes

# Columnas constantes en '0'
df_final.drop(['ratio_nullHyperlinks','ratio_intRedirection','ratio_intErrors','submit_email','sfh','f9','f12', 'f26','f27'], axis=1, inplace=True)
#print(df_final.head())

# Columnas con alta varizanza con status

highCorrDf = df_final[['ip', 'nb_www','nb_com', 'tld_in_path', 'tld_in_subdomain','abnormal_subdomain', 'prefix_suffix', 'shortening_service','length_words_raw', 'char_repeat'
, 'shortest_words_raw', 'shortest_word_host', 'longest_words_raw', 'longest_word_path', 'avg_word_path', 'phish_hints', 'domain_in_brand', 'nb_hyperlinks', 'ratio_intHyperlinks'
, 'nb_extCSS', 'external_favicon', 'links_in_tags', 'ratio_intMedia', 'ratio_extMedia', 'safe_anchor', 'empty_title', 'domain_in_title', 'domain_with_copyright','domain_registration_length'
, 'domain_age', 'web_traffic', 'google_index', 'page_rank', 'f1', 'f2', 'f4', 'f6', 'f7', 'f8', 'f10', 'f14', 'f18']]
#print(highCorrDf.head())


#print(highCorrDf.dtypes)

print("PARTE 1 Finalizada")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------


# PARTE 2
print('PARTE 2 COMENZADA')
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

# PARTE 2: SEPARACION DE DATOS
target = df_final['status']
#print(highCorrDf, target)
#feature_matrix_train, feature_matrix_test, target_train, target_test = model_selection.train_test_split(highCorrDf, target, test_size=0.30, random_state=123)

#11430
def train_validate_test_split(df, train_percent=.55, validate_percent=.15, seed=123):
    np.random.seed(seed)
    perm = np.random.permutation(df.index)
    m = len(df.index)
    train_end = int(train_percent * m)
    validate_end = int(validate_percent * m) + train_end
    train = df.iloc[perm[:train_end]]
    validate = df.iloc[perm[train_end:validate_end]]
    test = df.iloc[perm[validate_end:]]
    return train, validate, test

#train, validate, test = train_validate_test_split(highCorrDf)
#print(train, validate, test)

#55% de entrenamiento y 45% para validación y pruebas.
#45y55
x_train, x_val_test, y_train, y_val_test = model_selection.train_test_split(highCorrDf, target, test_size = 0.45, random_state=123)

#segunda separación se puede hacer en 33% y 67% respectivamente. 
x_val, x_test, y_val, y_test = model_selection.train_test_split(x_val_test, y_val_test, test_size = 0.33, random_state=123)

clf = tree.DecisionTreeClassifier()
#clf = clf.fit(feature_matrix_train, target_train)
clf = clf.fit(x_train,y_train)

print("PARTE 2: SEPARACION DE DATOS TERMINADA")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

#print(feature_matrix_train.count())
#print(feature_matrix_test.count())

# PARTE2 : IMPLEMENTACION

#  x_train y se predice contra x_val.

print("PARTE 2: Validacion")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")


# validacion (15%)
#target_pred = clf.predict(feature_matrix_test)
target_pred = clf.predict(x_val)
#print(metrics.accuracy_score(target_test, target_pred))
print('Accuracy: ', metrics.accuracy_score(y_val, target_pred))
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
#print('Matriz de confusion \n',metrics.confusion_matrix(target_test, target_pred))
print('Matriz de confusion \n',metrics.confusion_matrix(y_val, target_pred))
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
#print(metrics.classification_report(target_test, target_pred, target_names=['legitimate', 'Phishing']))
print(metrics.classification_report(y_val, target_pred, target_names=['Legitimate', 'Phishing']))
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")


print("PARTE 2: Test")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

# test (30%)
#target_pred = clf.predict(feature_matrix_test)
target_pred_test = clf.predict(x_test)
#print(metrics.accuracy_score(target_test, target_pred))
print('Accuracy: ', metrics.accuracy_score(y_test, target_pred_test))
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
#print('Matriz de confusion \n',metrics.confusion_matrix(target_test, target_pred))
print('Matriz de confusion \n',metrics.confusion_matrix(y_test, target_pred_test))
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
#print(metrics.classification_report(target_test, target_pred, target_names=['legitimate', 'Phishing']))
print(metrics.classification_report(y_test, target_pred_test, target_names=['Legitimate', 'Phishing']))
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

print("PARTE 2: IMPLEMENTACION TERMINADA")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("fin :)")

#Si los resultados son aceptables, se procede a predecir contra x_test
