#ifndef DATASET_EXPORTER_H
#define DATASET_EXPORTER_H

/*
  Builds a dataset CSV from two folders:
  - benign files → label 0
  - malicious files → label 1
*/
int build_dataset_from_directories(const char *benign_dir,
                                   const char *malicious_dir,
                                   const char *csv_path);

#endif