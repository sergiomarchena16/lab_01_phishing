
# Lab 01 - Deteccion de Phishing
# SERGIO MARCHENA - 16387
# SECURITY DATA SCIENCE

import pandas as pd
import numpy as np
import sklearn as sk
import  matplotlib.pyplot as plt
import pandas_profiling as pp
from pandas_profiling import ProfileReport

# PARTE 1

# EXPLORACION DE DATOS

df = pd.read_csv("C:\\Users\\sergi\\Desktop\\UVG\\2022\\SECURITY DATA SCIENCE\\lab_01_phishing\\lab_01_phishing\\dataset_pishing.csv", encoding="utf-8")
df.head()

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


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# VISUALIZACION DE RESULTADOS

# Features finales
df_final = df
finalFeatures = df_final.columns
print('final features:' , finalFeatures)

print("hola")
print(df_final)

'''

#pip install -U pandas-profiling

# Reporte

profile2 = ProfileReport(df)
profile2.to_file('Reporte de data de Phishing (sample).html')

'''

#print(pd.__version__)
#!pip freeze |grep pandas-profiling

# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# SELECCION DE CARACTERISTICAS





# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------


# PARTE 2