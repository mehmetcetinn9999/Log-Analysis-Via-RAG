"""
Predictive Log Analysis via RAG
Sistem loglarını analiz eden RAG tabanlı güvenlik asistanı
"""

import streamlit as st
import tempfile
import re
from datetime import datetime

# Streamlit konfigürasyonu
st.set_page_config(
    page_title="Log Analiz RAG - Güvenlik Asistanı",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 Predictive Log Analysis via RAG")
st.markdown("""
**Sistem loglarını yükleyin ve doğal dil ile sorgulayın**
- 📁 Log dosyalarını yükleyin
- 💬 Saldırı vektörlerini sorgulayın
- 📎 Kanıt bazlı yanıtlar alın
""")

# ChromaDB ve embedding'leri başlat
@st.cache_resource
def init_vectorstore():
    import chromadb
    from chromadb.utils import embedding_functions
    
    client = chromadb.PersistentClient(path="./log_vectorstore")
    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )
    return client, embedding_fn

# Log yükleme
uploaded_file = st.file_uploader(
    "📂 Sistem Log Dosyası Yükle",
    type=["log", "txt"],
    help=".log, .txt uzantılı dosyaları yükleyebilirsiniz"
)

if uploaded_file:
    # Dosyayı oku
    content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
    lines = [l.strip() for l in content.split("\n") if l.strip()]
    
    st.success(f"✅ {len(lines)} satır log yüklendi")
    
    # Log önizleme
    with st.expander("📄 Log Önizleme (ilk 15 satır)"):
        st.code("\n".join(lines[:15]))
    
    # İndeksleme
    if st.button("🚀 Logları İndeksle ve Analize Hazırla", type="primary"):
        with st.spinner(f"{len(lines)} satır indeksleniyor..."):
            client, embedding_fn = init_vectorstore()
            
            # Eski koleksiyonu sil
            try:
                client.delete_collection("log_analysis")
            except:
                pass
            
            # Yeni koleksiyon oluştur
            collection = client.create_collection(
                name="log_analysis",
                embedding_function=embedding_fn
            )
            
            # Logları ekle (batch halinde)
            batch_size = 100
            for i in range(0, len(lines), batch_size):
                batch = lines[i:i+batch_size]
                
                # IOC'leri tespit et (IP adresleri)
                iocs = []
                for log in batch:
                    ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', log)
                    if ips:
                        iocs.append(", ".join(ips))
                    else:
                        iocs.append("")
                
                collection.add(
                    documents=batch,
                    ids=[f"log_{i+j}" for j in range(len(batch))],
                    metadatas=[
                        {
                            "index": i+j, 
                            "content": txt[:200],
                            "iocs": iocs[j] if iocs[j] else "none",
                            "severity": "ERROR" if "error" in txt.lower() else "WARNING" if "warn" in txt.lower() else "INFO"
                        }
                        for j, txt in enumerate(batch)
                    ]
                )
            
            st.session_state.collection = collection
            st.session_state.log_count = len(lines)
            st.session_state.log_lines = lines
            st.success(f"✅ {len(lines)} log başarıyla indekslendi!")

# Sorgulama
if "collection" in st.session_state:
    st.divider()
    st.markdown("### 💬 Doğal Dil ile Sorgulama")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        question = st.text_input(
            "Sorunuzu yazın:",
            placeholder="Örn: Hangi IP adresleri başarısız giriş denemesi yaptı? veya Şüpheli aktiviteleri listele"
        )
    with col2:
        k = st.slider("Sonuç sayısı", 1, 10, 5)
    
    # Örnek sorgu önerileri
    with st.expander("💡 Örnek sorgular"):
        st.markdown("""
        - `Başarısız giriş denemelerini ve kaynak IP adreslerini listele`
        - `Hangi IP adresleri engellenmiş (BLOCKED) ve neden?`
        - `SQL injection veya şüpheli aktiviteleri göster`
        - `Olası saldırı vektörleri nelerdir?`
        - `Son 1 saatteki hataları göster`
        """)
    
    if question:
        with st.spinner("🔍 Loglar aranıyor..."):
            results = st.session_state.collection.query(
                query_texts=[question],
                n_results=k
            )
        
        if results['documents'][0]:
            st.markdown(f"### 📝 En İlgili {len(results['documents'][0])} Log Kaydı")
            
            for i, (doc, dist, meta) in enumerate(zip(
                results['documents'][0],
                results['distances'][0],
                results['metadatas'][0]
            )):
                score = 1 - (dist / 2)
                color = "🟢" if score > 0.7 else "🟡" if score > 0.5 else "🟠"
                
                with st.expander(f"{color} Sonuç {i+1} | Benzerlik: {score:.2f} | Severity: {meta.get('severity', 'N/A')}"):
                    st.code(doc)
                    st.caption(f"Satır: {meta['index']}")
                    if meta.get('iocs') and meta['iocs'] != 'none':
                        st.warning(f"🌐 Tespit edilen IOC'ler (IP): {meta['iocs']}")
        else:
            st.info("İlgili log bulunamadı. Farklı bir soru deneyin.")
    
    # Dashboard bilgisi
    with st.expander("📊 İndeks İstatistikleri"):
        col1, col2, col3 = st.columns(3)
        col1.metric("Toplam Log Sayısı", st.session_state.log_count)
        col2.metric("Vektör Veritabanı", "ChromaDB")
        col3.metric("Embedding Modeli", "all-MiniLM-L6-v2")

# Sidebar bilgisi
with st.sidebar:
    st.markdown("### 🛡️ Sistem Bilgisi")
    st.markdown("""
    - **RAG Pipeline:** LangChain + ChromaDB
    - **Embedding:** Sentence Transformers
    - **Arama:** Anlam bazlı vektör araması
    - **Output:** Kanıt bazlı cevaplar
    """)
    
    st.markdown("### 📚 Nasıl Çalışır?")
    st.markdown("""
    1. **Loglar** vektör veritabanına indekslenir
    2. **Sorgunuz** vektöre çevrilir
    3. **En benzer loglar** bulunur
    4. **Kanıtlar** gösterilir
    """)
