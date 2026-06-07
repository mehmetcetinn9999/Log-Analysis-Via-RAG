"""
Kendi sistem loglarını yüklemek için özel ingest script'i
"""

import os
from langchain_community.document_loaders import TextLoader, DirectoryLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

def load_my_logs(log_directory="data/my_logs/"):
    """
    Kendi log dosyalarını yükler ve parçalara ayırır
    """
    # Tüm .log dosyalarını yükle
    loader = DirectoryLoader(
        log_directory,
        glob="**/*.log",
        loader_cls=TextLoader,
        loader_kwargs={"encoding": "utf-8"}
    )
    
    documents = loader.load()
    print(f"📁 {len(documents)} dosya yüklendi")
    
    # Logları parçalara ayır (her satır ayrı bir parça olabilir)
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=500,      # Her parça max 500 karakter
        chunk_overlap=50,    # Parçalar arası 50 karakter örtüşme
        separators=["\n", ".", " "]  # Önce satır sonlarından ayır
    )
    
    chunks = text_splitter.split_documents(documents)
    print(f"✂️ {len(chunks)} parçaya ayrıldı")
    
    # Her parçaya metadata ekle
    for chunk in chunks:
        # Dosya adından log_source çıkar
        source = chunk.metadata.get("source", "")
        chunk.metadata["log_source"] = os.path.basename(source)
        
        # Severity bul (ERROR, WARNING, INFO, vb.)
        content = chunk.page_content.lower()
        if "error" in content:
            chunk.metadata["severity"] = "ERROR"
        elif "warn" in content:
            chunk.metadata["severity"] = "WARNING"
        elif "failed" in content or "blocked" in content:
            chunk.metadata["severity"] = "ALERT"
        else:
            chunk.metadata["severity"] = "INFO"
        
        # Timestamp varsa ekle (basit regex)
        import re
        timestamp_match = re.search(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', content)
        if timestamp_match:
            chunk.metadata["timestamp"] = timestamp_match.group()
    
    return chunks

if __name__ == "__main__":
    chunks = load_my_logs()
    for chunk in chunks[:3]:
        print(f"\n📝 Kaynak: {chunk.metadata.get('log_source')}")
        print(f"⚠️ Severity: {chunk.metadata.get('severity')}")
        print(f"📄 İçerik: {chunk.page_content[:100]}...")
