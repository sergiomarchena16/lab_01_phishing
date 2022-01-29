# Laboratorio 1 de Security Data Science
#### Sergio Marchena - 16387

## Exploracion de datos
```bash
legitimate    5715
phishing      5715
```
#### El dataset esta balanceado exactamente en 50/50, es decir, el 50% de las observaciones esta categorizada como phishing y el otro 50% esta clasificado como legitimate, para un total de 11,430 observaciones.

# Resultados y Discusion

#### Contra la data de validacion (15%), el modelo de Arboles de Decision tuvo:

```bash
Accuracy:  0.9263406010606954
```
#### Contra la data de prubea (30%), el modelo de Arboles de Decision tuvo:

```bash
Accuracy:  0.9239918769944879
```
## Metricas

#### Para la fase de validacion de obtuvieron los siguientes resultados:
```bash
Matriz de confusion 
 [[793  65]
 [ 60 779]]
```
```bash
              precision    recall  f1-score   support

  Legitimate       0.93      0.92      0.93       858
    Phishing       0.92      0.93      0.93       839

    accuracy                           0.93      1697
   macro avg       0.93      0.93      0.93      1697
weighted avg       0.93      0.93      0.93      1697
```

#### Para la fase de pruebas de obtuvieron los siguientes resultados:
```bash
Matriz de confusion 
 [[1602  134]
 [ 128 1583]]
```
```bash
              precision    recall  f1-score   support

  Legitimate       0.93      0.92      0.92      1736
    Phishing       0.92      0.93      0.92      1711

    accuracy                           0.92      3447
   macro avg       0.92      0.92      0.92      3447
weighted avg       0.92      0.92      0.92      3447
```
##### La matriz de confusion nos provee un resumen de las predicciones del modelo predictivo. 
  - En el caso de la validacion, el modelo calculo 793 sitios legitimos verdaderos y 779 sitios de phishing verdaderos. Por otro lado, calculo 65 sitios como falsos positivos y 60 como falsos negativos.
  - En el caso de la prueba, el modelo calculo 1602 sitios legitimos verdaderos y 1583 sitios de phishing verdaderos. Por otro lado, calculo 134 sitios como falsos positivos y 128 como falsos negativos.

##### La precision de los modelos es importante ya que nos indica que proporción de los casos identificados como positivos fue correcta realmente. 
  - En el caso de la *validacion y prueba*, el modelo tuvo una precision de 93% para sitios legitimos y un 92% para sitios de phishing. Esto quiere decir que cuando nuestro modelo identifica un sitio como legitimo, es correcto el 93% de las veces y cuando nuestro modelo identifica un sitio como phishing, es correcto el 92% de las veces.

##### El recall es una metrica que nos indica la proporción de los positivos que fue identificada correctamente. 
  - En el caso de *validacion y prueba*, el modelo identifica correctamente 92% de todos los sitios legítimos e identifica correctamente 93% de todos los sitios de phishing.

##### El valor de F1 es un promedio de ambas métricas (precision y recall) dandole a ambas métricas la misma importancia. Esta métrica es útil cuando necesitamos un equilibrio entre precision y recall y hay desbalance en la data.
  - El modelo tiene un valor de f1 de 93 para sitios legitimos y phishing contra la data de validacion.
  - El modelo tiene un valor de f1 de 92 para sitios legitimos y phishing contra la data de prueba.

## Pregutas finales:

> #### 1. ¿Cuál es el impacto de clasificar un sitio legítimo como Pishing?

El impacto seria muy malo para los usuarios de esa pagina web. Asi mismo puede ser muy grave para empresas o personas que tengan un tipo de negocio o informacion dentro de esa pagina, ya que no tendria visitas y las personas no entrarian ni confiarian en este sitio.

> #### 2. ¿Cuál es el impacto de clasificar un sitio de Pishing como legítimo?

Es muy malo para los usuarios, ya que se confiaria en los sitios no legitimos y esto solo causaria que las personas sean enganadas, robadas o estafadas en algunos casos. Habria muchos robos de informacion.

> #### 3. En base a las respuestas anteriores, ¿Qué métrica elegiría para comparar modelos similares de clasificación de pishing?

Eligiria un promedio de las metricas. Es decir el f1-score, ya que las dos son importantes y no se puede dar a una de menos. Creo que lo mejor seria ambas con la misma importancia.

> #### 4. ¿Es necesaria la intervención de una persona humana en la decisión final de clasificación?

Creo que al final, si se quiere detener el phishing en sitios web, el programa para detectar phishing debe de tener una buena certeza y si, al final deberia de haber una persona checando los falsos positivos y negativos, pero ya serian menos que intervenir cuando no se ha usado un modelo de prediccion. 
