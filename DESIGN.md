---
name: GeekNosy
description: Mesa de control para auditorias web responsables, reproducibles y con autorizacion explicita.
colors:
  ink: "#142033"
  ink-soft: "#445268"
  paper: "#f4f2ec"
  surface: "#fffefa"
  surface-muted: "#e8e5dc"
  line: "#c9c5ba"
  line-strong: "#8f908c"
  permit-orange: "#e6531f"
  permit-orange-strong: "#bd3810"
  verified-green: "#177253"
  risk-red: "#b7272f"
  review-amber: "#9b6500"
  focus-blue: "#1d66c2"
  rail-navy: "#132238"
  rail-muted: "#9dadc2"
typography:
  display:
    fontFamily: "Archivo Variable, Archivo, sans-serif"
    fontSize: "clamp(2.375rem, 5vw, 4.25rem)"
    fontWeight: 780
    lineHeight: 1.04
    letterSpacing: "-0.032em"
  headline:
    fontFamily: "Archivo Variable, Archivo, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 740
    lineHeight: 1.04
    letterSpacing: "-0.032em"
  body:
    fontFamily: "IBM Plex Sans Variable, IBM Plex Sans, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "IBM Plex Sans Variable, IBM Plex Sans, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 760
    lineHeight: 1.3
    letterSpacing: "0.07em"
rounded:
  square: "0px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "18px"
  xl: "24px"
  panel: "34px"
components:
  button-primary:
    backgroundColor: "{colors.permit-orange}"
    textColor: "{colors.surface}"
    typography: "{typography.label}"
    rounded: "{rounded.square}"
    padding: "10px 17px"
    height: "46px"
  button-primary-hover:
    backgroundColor: "{colors.permit-orange-strong}"
    textColor: "{colors.surface}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.square}"
    padding: "10px 17px"
    height: "46px"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.square}"
    padding: "10px 11px"
    height: "43px"
  panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.square}"
    padding: "34px"
  mode-chip:
    backgroundColor: "#dbeee5"
    textColor: "#115b42"
    typography: "{typography.label}"
    rounded: "{rounded.square}"
    padding: "4px 8px"
---

# Design System: GeekNosy

## Overview

**Creative North Star: "El Permiso de Trabajo Industrial"**

GeekNosy se siente como una mesa de control donde cada auditoria se abre, delimita y documenta antes de ejecutarse. Su mundo visual toma del papel de inspeccion, la tinta naval y las senales de seguridad: preciso, sobrio y operativo, sin adoptar la estetica de terminal oscura ni el dramatismo del "hacker dashboard".

La densidad es deliberada pero legible. Cada superficie debe ayudar a distinguir alcance, evidencia, estado y autorizacion. El naranja aparece como una accion consciente; verde, ambar y rojo comunican condicion, nunca decoracion. La interfaz privilegia bordes, divisores y jerarquia tipografica sobre efectos ornamentales.

**Key Characteristics:**

- Papel tecnico claro con una columna naval de control.
- Titulares compactos en Archivo y lectura operativa en IBM Plex Sans.
- Bordes rectos, etiquetas recortadas y ritmo de formulario industrial.
- Acciones activas separadas visual y operacionalmente del analisis pasivo.
- Estados comunicados con texto, forma y color; nunca solo con color.

## Colors

La paleta combina tinta naval, papel calido y un naranja de permiso reservado para decisiones de alto valor.

### Primary

- **Naranja de Permiso:** activa la accion primaria, los controles seleccionados y los indicadores de trabajo en curso.
- **Tinta de Registro:** sostiene titulares, tablas, botones de contraste y contenido de maxima prioridad.

### Secondary

- **Naval de Control:** construye la barra lateral y separa la navegacion persistente del area de trabajo.
- **Azul de Foco:** identifica el foco de teclado y la progresion sin confundirse con los estados de seguridad.

### Tertiary

- **Verde Verificado:** comunica condiciones aprobadas o saludables.
- **Ambar de Revision:** comunica resultados que requieren criterio humano.
- **Rojo de Riesgo:** comunica errores y hallazgos severos.

### Neutral

- **Papel de Inspeccion:** es el fondo general y evita el blanco clinico.
- **Hoja de Trabajo:** contiene formularios, paneles e historial.
- **Linea de Archivo:** divide campos y grupos sin producir ruido.
- **Tinta Suave:** reserva contraste secundario para ayuda y metadatos.

**The Permit Orange Rule.** El naranja se reserva para una accion primaria, seleccion activa o progreso; no se usa para decorar superficies completas.

**The Evidence Color Rule.** Verde, ambar y rojo siempre aparecen junto a una etiqueta, numero o mensaje que conserve el significado sin color.

## Typography

**Display Font:** Archivo Variable (con Archivo y sans-serif como respaldo)

**Body Font:** IBM Plex Sans Variable (con IBM Plex Sans y sans-serif como respaldo)

**Label Font:** IBM Plex Sans Variable

**Character:** Archivo aporta autoridad compacta a los titulos; IBM Plex Sans mantiene formularios, evidencia y tablas tecnicos pero humanos. Ambas fuentes se sirven localmente para que Docker no dependa de un proveedor externo.

### Hierarchy

- **Display** (780, escala fluida, 1.04): una sola declaracion principal por vista.
- **Headline** (740, 1.5rem, 1.04): titulos de panel y secciones de trabajo.
- **Title** (700, 1.0625rem, 1.04): bloques autorizados y agrupaciones internas.
- **Body** (400, 0.9375rem, 1.5): instrucciones, evidencia y explicaciones; limitar parrafos largos a unas 68 letras.
- **Label** (760, 0.6875rem, 0.07em): nombres de campo y metadatos en mayusculas.

**The One Declaration Rule.** Cada pantalla tiene un solo titular de escala display; la interfaz operativa restante usa headline, title y label.

## Layout

En escritorio, una barra persistente de 232px contiene identidad, navegacion, salud del servicio y autoria. El escenario central admite hasta 1480px y usa una mesa de trabajo de dos columnas: el permiso de analisis ocupa el espacio flexible y el limite operativo se mantiene entre 270px y 340px.

El ritmo base se apoya en saltos de 8px, 12px, 18px y 24px. Los paneles principales usan hasta 34px de espacio interno. A 1100px la mesa pasa a una columna; a 820px la barra lateral se sustituye por un encabezado movil; a 560px los pasos, campos y acciones se apilan. Ninguna vista debe introducir desplazamiento horizontal global.

**The Scope Before Results Rule.** Alcance, modo y autorizacion aparecen antes de cualquier accion primaria o resultado.

## Elevation & Depth

El sistema es plano por defecto. Las superficies de trabajo principales usan una sombra ambiental tenue para separarse del papel; campos, tablas y controles dependen de bordes y cambios tonales. El foco de teclado utiliza un contorno azul explicito y no una sombra decorativa.

### Shadow Vocabulary

- **Panel ambiental** (`0 16px 34px rgba(34,41,52,.08)`): solo paneles principales sobre el fondo de papel.
- **Panel movil** (`0 10px 24px rgba(34,41,52,.07)`): reduccion de profundidad en pantallas pequenas.
- **Servicio operativo** (`0 0 0 3px rgba(66,197,138,.14)`): halo exclusivo del indicador de salud.

**The Flat Control Rule.** Botones, campos, chips y filas no reciben sombras en reposo; su estado se expresa con borde, tinta y tono.

## Shapes

La geometria es cuadrada. Los controles, paneles y etiquetas usan esquinas de 0px para recordar formularios de inspeccion y etiquetas industriales. Las separaciones se construyen con lineas de 1px; los circulos se reservan para indicadores de estado pequenos, no para botones o contenedores.

**The Square Record Rule.** Un componente operativo nuevo comienza con esquinas rectas y solo se redondea si su funcion exige una silueta circular reconocible.

## Components

### Buttons

- **Shape:** rectangular y firme, sin radio, con altura minima de 46px.
- **Primary:** naranja de permiso con texto claro y borde mas profundo; representa la decision de iniciar o confirmar.
- **Hover / Focus:** el hover profundiza el color; el foco conserva el contorno azul global de 3px; el estado deshabilitado reduce contraste y mantiene su etiqueta.
- **Secondary:** hoja de trabajo con borde fuerte; invierte a tinta oscura al pasar el puntero.

### Chips

- **Style:** etiquetas pequenas, cuadradas y de alto contraste, con texto en mayusculas y espaciado amplio.
- **State:** cada chip declara un modo o condicion; no funciona como ornamento ni reemplaza una explicacion.

### Cards / Containers

- **Corner Style:** esquinas rectas.
- **Background:** hoja de trabajo sobre papel de inspeccion.
- **Shadow Strategy:** solo los paneles de primer nivel usan la sombra ambiental.
- **Border:** linea de archivo de 1px.
- **Internal Padding:** entre 20px y 34px segun el ancho disponible.

### Inputs / Fields

- **Style:** fondo claro, borde fuerte, altura minima de 43px y etiqueta externa en mayusculas.
- **Focus:** borde azul con halo contenido de 2px, ademas del indicador global de teclado cuando corresponda.
- **Error / Disabled:** un bloque de error rojo incluye texto accionable; un control deshabilitado conserva contraste suficiente y cursor coherente.

### Navigation

La navegacion lateral usa iconos lineales cuadrados, texto compacto y una fila activa con fondo naval mas claro y borde visible. En movil se reduce a identidad y salud del servicio; los destinos operativos permanecen dentro del flujo de la pagina.

### Authorization Rail

El riel de tres pasos hace visible la secuencia alcance, perfil y autorizacion. El paso actual usa naranja claro, el completado usa verde claro y cada estado conserva texto y numero; nunca depende solo del color.

## Do's and Don'ts

### Do:

- **Do** mantener alcance, modo, evidencia y autorizacion visibles cerca de la accion que gobiernan.
- **Do** usar Archivo para jerarquia y IBM Plex Sans para lectura, formularios y datos.
- **Do** conservar un foco de teclado de 3px y objetivos interactivos de al menos 43px de alto.
- **Do** convertir la barra lateral en encabezado movil a 820px y apilar formularios complejos a 560px.
- **Do** usar iconos SVG lineales con significado accesible o `aria-hidden` cuando sean decorativos.

### Don't:

- **Don't** convertir GeekNosy en una terminal oscura, una reticula neon o un dashboard generico de ciberseguridad.
- **Don't** mezclar acciones pasivas y autorizadas dentro del mismo control ambiguo.
- **Don't** usar gradientes, vidrio, radios grandes o sombras intensas para crear jerarquia.
- **Don't** comunicar riesgo, salud o progreso unicamente mediante color.
- **Don't** cargar tipografias, iconos o activos esenciales desde servicios externos.
