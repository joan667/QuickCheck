#!/bin/bash

#Script para comprobar si en un archivo con una lista de ips hay alguna coincidencia con las listas publicas de firehol

#parametros:
#    1- nombre de la lista de firehol a comprobar ejemplo: firehol_level1.netset
#    2- nombre del archivo con la lista de ips a comprobar
#    3- para forzar que se descargue la ultima version de la lista, si no se coge la que ya esta bajada


rm -f suspicious_ips.txt 2> /dev/null

FHLIST=$1
IP_LIST=$2
FORCE_DOWNLOAD=$3

# Solo descargar si no existe ya
if [[ ! -f "$FHLIST" || "$FORCE_DOWNLOAD" == "1" ]]; then
  echo "Descargando $FHLIST..."
  #HINt: se esta usando las listas de firehol pero realmente se puede mirar de integrar con otras listas como las de stamparm
  wget "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/$FHLIST" #-O "$FHLIST" &> /dev/null
else
  echo "$FHLIST ya existe, no se descarga."
fi

# Crear carpetas y distribuir IPs para que las comprobaciones sean mas directas
echo "work in progress..."
while IFS= read -r ip; do
  # Saltar líneas vacías o que no sean IPv4 (como comentarios)
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]  || continue

  # Obtener primer octeto
  first_octet="${ip%%.*}"
  #echo $first_octet

  # Crear carpeta si no existe
  mkdir -p "temp/$first_octet"

  # Añadir IP al archivo correspondiente
  echo "$ip" >> "temp/$first_octet/lista.txt"
done < "$FHLIST"



#funciones para verificar que una ip este dentro de un cidr
ip_to_int() {
    local IFS=.
    read -r o1 o2 o3 o4 <<< "$1"
    echo $(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))
}

ip_in_cidr() {
    local ip=$1
    local cidr=$2

    local network="${cidr%/*}"
    local mask_bits="${cidr#*/}"

    # Verificar que máscara está entre 0–32
    [[ "$mask_bits" =~ ^[0-9]+$ ]] && (( mask_bits >= 0 && mask_bits <= 32 )) || return 1

    local ip_int network_int
    ip_int=$(ip_to_int "$ip") || return 1
    network_int=$(ip_to_int "$network") || return 1

    # Calcular la máscara de red como entero
    local mask=$(( 0xFFFFFFFF << (32 - mask_bits) & 0xFFFFFFFF ))

    # Aplicar máscara y comparar
    if (( (ip_int & mask) == (network_int & mask) )); then
        return 0
    else
        return 1
    fi
}

# Procesar cada IP de entrada
while read -r ip; do
    # si en la lista hay algo que no sea una ip, passamos
    [[ -z "$ip" || ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && continue
   
    first_octet="${ip%%.*}"

    in_lvl1=0
    file="temp/$first_octet/lista.txt"
    if [[ -f "$file" ]]; then
      while read -r cidr; do
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ip_in_cidr "$ip" "$cidr/32" && { in_lvl1=1; break; }
        [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]] && ip_in_cidr "$ip" "$cidr" && { in_lvl1=1; break; }
     done < "$file"
    fi

    #lo guardamos en el archivo suspicious_ips.txt si ha salido en el nivel 1 ponemos <IP>,1.  si sale en el 2 <IP>,2 en ambos <IP>,3
   
    num=0
   
    if [[ $in_lvl1 -eq 1 ]]; then
        num=$((num + 1))
    fi
       
    #if [[ !$num -eq 0 ]]; then
    echo "$ip,$num"
    echo "$ip,$num" >> suspicious_ips.txt
    #fi
   
done < "$IP_LIST"

echo "done!"
rm -rf temp
