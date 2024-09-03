
import cv2
import numpy as np
import time

def collect_biometric_data(cascade_path='haarcascade_frontalface_default.xml'):
    # Yüz tanıma için Haar Cascade sınıflandırıcısını yükle
    face_cascade = cv2.CascadeClassifier(cascade_path)
    
    # Kamerayı aç
    cap = cv2.VideoCapture(0)
    
    if not cap.isOpened():
        print("Kameraya erişilemiyor.")
        return None
    
    print("Lütfen yüzünüzü kameraya yönlendirin ve 'q' tuşuna basın.")
    
    face_captured = False
    captured_frame = None
    
    while True:
        # Kameradan kareyi yakala
        ret, frame = cap.read()
        
        if not ret:
            print("Kare alınamadı.")
            break
        
        # Gri tonlamaya dönüştür
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        
        # Yüzleri algıla
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.3, minNeighbors=5)
        
        # Algılanan her yüz için yeşil kare çiz
        for (x, y, w, h) in faces:
            cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
        
        # Kareyi göster
        cv2.imshow('Biyometrik Veri Toplama - Yüzünüzü Görüntüleyin', frame)
        
        # 'q' tuşuna basıldığında yüzü yakala
        if cv2.waitKey(1) & 0xFF == ord('q'):
            if len(faces) == 0:
                print("Yüz algılanamadı. Lütfen tekrar deneyin.")
                continue
            print("Yüz algılandı ve yakalanıyor...")
            face_captured = True
            captured_frame = frame.copy()
            break
    
    # Kaynakları serbest bırak
    cap.release()
    cv2.destroyAllWindows()
    
    if face_captured:
        # 1 saniye bekle
        time.sleep(1)
        
        # Yakalanan kareyi gri tonlamaya dönüştür
        gray_captured = cv2.cvtColor(captured_frame, cv2.COLOR_BGR2GRAY)
        
        # Yüz bölgesini kes (ilk algılanan yüzü kullan)
        (x, y, w, h) = faces[0]
        face_region = gray_captured[y:y+h, x:x+w]
        
        # Yüz bölgesini yeniden boyutlandır (128x128)
        resized_face = cv2.resize(face_region, (128, 128))
        
        # Veriyi düzleştir ve byte dizisine dönüştür
        biometric_data = resized_face.flatten().tobytes()
        
        print("Biyometrik veri başarıyla alındı.")
        return biometric_data
    else:
        print("Biyometrik veri alınamadı.")
        return None

if __name__ == "__main__":
    bio_data = collect_biometric_data()
    if bio_data:
        print(f"Toplanan Biyometrik Veri: {bio_data[:10]}... (kısaltıldı)")
