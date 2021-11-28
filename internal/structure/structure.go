package structure

import (
	"errors"
	"fmt"
	"log"
	"os"
)

// Check if theres a Directory and a file
// REMEMBER SR
func Exist(path string) (esta bool, err error) {
	if _, err := os.Stat(path); err == nil {
		// path exists
		//log.Print("Path existe: ", absDir)
		esta = true
		return esta, err
	} else if errors.Is(err, os.ErrNotExist) {
		// path not exist
		esta = false
		return esta, err
	}
	return esta, err

}

// if the dir or file doesnt exist create it or just leave
func CreaFiles(path string) (bool, error) {
	_, err := Exist(path)
	if err != nil {
		// log.Print("Path no Existe Creando Archivo")
		file, err1 := os.Create(path)
		if err1 != nil {
			log.Printf("%v", err)
		}
		defer file.Close()
		return true, err
	}
	return false, err

}

func CreaDirs(path string) (bool, error) {
	_, err := Exist(path)
	if err != nil {
		// log.Print("Path no Existe Creando Directorio")
		err1 := os.MkdirAll(path, 0777)
		if err1 != nil {
			//fmt.Println("Esta path ", path)
			fmt.Errorf("%v", err)
		}
		return true, err
	}
	return false, err

}

// Funcion que pone en funcionamiento la creacion de la estructura de los proyectos
// en caso de pasar solo un directorio solo crea el directorio
// en caso de que pasemos solo archivo creara el archivo desde la rot
func CreaDual(path, file string) (valor bool) {
	root, err := os.Getwd()
	if err != nil {
		log.Print("Ocurrion un Error mientras Wd")
	}
	if path != "/" && path != "" {
		_, err = CreaDirs(root + "/" + path)
		if err != nil {
			log.Print("Directorio inexistente: " + root + "/" + path + ", creandolo")
			valor = true
		}
	} else {
		_, err = CreaDirs(root + path)
		if err != nil {
			log.Print("Directorio inexistente: " + root + "/" + path + ", creandolo")
			valor = true
		}
	}
	if file != "" {
		fileDir := root + "/" + path + "/" + file
		_, err = CreaFiles(fileDir)
		if err != nil {
			log.Print("Archivo inexistente: " + fileDir + ", creandolo")
			valor = true

		}
	}
	return valor

}
