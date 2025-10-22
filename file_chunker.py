import os
import hashlib
import glob
import shutil

def get_valid_file_path():
    """Prompt user for a file path with proper validation"""
    while True:
        file_path = input("Enter file path (put in quotes if it contains spaces): ").strip()
        
        # Remove surrounding quotes if present
        if (file_path.startswith('"') and file_path.endswith('"')) or \
           (file_path.startswith("'") and file_path.endswith("'")):
            file_path = file_path[1:-1]
        
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found. Please try again.")
        elif os.path.isdir(file_path):
            print(f"Error: '{file_path}' is a directory, not a file.")
        else:
            return os.path.abspath(file_path)

def split_file(input_path, chunk_size=256*1024):
    """Split any file into numbered chunks"""
    chunk_dir = f"{input_path}_chunks"
    os.makedirs(chunk_dir, exist_ok=True)
    
    chunks = []
    with open(input_path, 'rb') as f:
        chunk_num = 1
        file_size = os.path.getsize(input_path)
        while True:
            chunk_data = f.read(chunk_size)
            if not chunk_data:
                break
            
            original_size = len(chunk_data)
            is_last_chunk = f.tell() == file_size
            
            # Debug info
            print(f"\nChunk {chunk_num}:")
            print(f"Original size: {original_size} bytes")
            print(f"Is last chunk: {is_last_chunk}")
            
            # Only pad if not last chunk and size < chunk_size
            if not is_last_chunk and original_size < chunk_size:
                chunk_data += b'\0' * (chunk_size - original_size)
                print(f"Padded to: {len(chunk_data)} bytes")
            
            chunk_name = f"{os.path.basename(input_path)}_chunk_{chunk_num:03d}.tmp"
            chunk_path = os.path.join(chunk_dir, chunk_name)
            
            with open(chunk_path, 'wb') as chunk_file:
                chunk_file.write(chunk_data)
            
            # Verify chunk immediately after writing
            with open(chunk_path, 'rb') as verify_file:
                verify_data = verify_file.read()
                verify_hash = hashlib.sha1(verify_data).hexdigest()
                print(f"Chunk hash: {verify_hash}")
                if verify_hash != hashlib.sha1(chunk_data).hexdigest():
                    print("WARNING: Chunk verification failed!")
            
            chunks.append({
                'path': chunk_path,
                'num': chunk_num,
                'original_size': original_size,
                'hash': hashlib.sha1(chunk_data).hexdigest(),
                'is_last': is_last_chunk
            })
            chunk_num += 1
    
    return chunks

def recombine_files(chunk_dir, output_path):
    """Recombine chunks into original file with detailed verification"""
    try:
        chunk_files = sorted(
            glob.glob(os.path.join(chunk_dir, "*.tmp")),
            key=lambda x: int(x.split('_chunk_')[-1].split('.')[0])
        )
        
        if not chunk_files:
            raise ValueError("No chunk files found in directory")
        
        print("\nRecombination process:")
        total_bytes = 0
        with open(output_path, 'wb') as out_file:
            for chunk_path in chunk_files:
                with open(chunk_path, 'rb') as chunk:
                    data = chunk.read()
                    chunk_num = int(chunk_path.split('_chunk_')[-1].split('.')[0])
                    
                    # Debug info
                    print(f"\nProcessing chunk {chunk_num}:")
                    print(f"Size read: {len(data)} bytes")
                    print(f"Hash: {hashlib.sha1(data).hexdigest()}")
                    
                    # Check if this is the last chunk by filename pattern
                    is_last_chunk = (chunk_num == len(chunk_files))
                    
                    # If not last chunk, verify size matches expected
                    if not is_last_chunk and len(data) != 256*1024:
                        print(f"WARNING: Chunk {chunk_num} size mismatch! Expected {256*1024}, got {len(data)}")
                    
                    # Write original data (without padding)
                    if is_last_chunk:
                        out_file.write(data)
                    else:
                        # For non-last chunks, write only original_size bytes
                        original_size = os.path.getsize(chunk_path)
                        if b'\0' in data:
                            original_size = data.find(b'\0')
                            if original_size == -1:
                                original_size = len(data)
                        out_file.write(data[:original_size])
                    
                    total_bytes += original_size
                    print(f"Written {original_size} bytes to output")
        
        print(f"\nTotal bytes written: {total_bytes}")
        return True
    except Exception as e:
        print(f"\nRecombination failed: {str(e)}")
        print("Debug info:")
        print(f"Chunk files found: {len(chunk_files)}")
        if chunk_files:
            print("First chunk:", chunk_files[0])
            print("Last chunk:", chunk_files[-1])
        return False

def main():
    print("=== File Chunker/Recombiner ===")
    print("This program will split a file into chunks and recombine them.\n")
    
    # Get input file
    input_file = get_valid_file_path()
    print(f"\nProcessing file: {input_file}")
    print(f"File size: {os.path.getsize(input_file):,} bytes")
    
    # Split file with detailed output
    print("\nSplitting file...")
    chunks = split_file(input_file)
    print(f"\nCreated {len(chunks)} chunks in directory: {input_file}_chunks")
    
    # Recombine with verification
    output_file = f"{input_file}.recombined"
    print("\nRecombining chunks...")
    success = recombine_files(f"{input_file}_chunks", output_file)
    
    if success:
        # Verification
        print("\nRunning verification...")
        original_hash = hashlib.sha1(open(input_file, 'rb').read()).hexdigest()
        recombined_hash = hashlib.sha1(open(output_file, 'rb').read()).hexdigest()
        
        print("\nVerification Results:")
        print(f"Original file hash: {original_hash}")
        print(f"Recombined file hash: {recombined_hash}")
        print("Status:", "SUCCESS" if original_hash == recombined_hash else "FAILED")
        
        # Compare file sizes
        original_size = os.path.getsize(input_file)
        recombined_size = os.path.getsize(output_file)
        print(f"\nOriginal size: {original_size} bytes")
        print(f"Recombined size: {recombined_size} bytes")
        print("Size match:", original_size == recombined_size)
        
        # Binary comparison
        print("\nRunning binary comparison...")
        with open(input_file, 'rb') as f1, open(output_file, 'rb') as f2:
            byte_count = 0
            while True:
                b1 = f1.read(1)
                b2 = f2.read(1)
                if not b1 and not b2:
                    break
                if b1 != b2:
                    print(f"First difference at byte {byte_count}:")
                    print(f"Original: {b1.hex()} | Recombined: {b2.hex()}")
                    break
                byte_count += 1
            else:
                print("Binary comparison: Files are identical")
    
    print("\nProcess complete. No files were deleted automatically.")

if __name__ == "__main__":
    main()