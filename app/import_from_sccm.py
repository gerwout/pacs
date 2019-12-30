from app.utils.import_handler import import_handler

def main():
  sccm_import = import_handler()
  message = sccm_import.import_from_sccm_and_ad()

  print(message)

if __name__ == "__main__":
    main()