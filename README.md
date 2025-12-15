# 🗑️ RecycleBin Forensic Explorer

  ![](/Screenshots/banner.png)

**A hassle-free GUI tool for Windows Recycle Bin forensic analysis - Browse deleted files without complex $I/$R parsing**

  

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)

[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[![Forensics](https://img.shields.io/badge/Category-Digital%20Forensics-red)](https://github.com/akhil-dara)

  

## 🎯 Overview

  

RecycleBin Forensic Explorer is a  user-friendly GUI application designed to quickly explore recycle bin from E01 forensic images for digital forensic investigators and cybersecurity professionals. This tool eliminates the complexity of manually parsing Windows Recycle Bin artifacts ($I and $R files) by providing an intuitive interface for quick browsing, analysis, and export of deleted file metadata.

  

### Why RecycleBin Forensic Explorer?

 
Traditional Recycle Bin forensics requires:

- ❌ Manual parsing of binary $I files for metadata extraction

- ❌ Complex command-line tools and scripts

- ❌ Matching $I files with corresponding $R files

- ❌ Time-consuming manual correlation of deleted file artifacts

  

**RecycleBin Forensic Explorer solves this by:**

- ✅ **One-click analysis** of entire Recycle Bin structures

- ✅ **Visual evidence tree** showing all deleted items instantly

- ✅ **Automatic $I/$R file parsing** with no manual intervention

- ✅ **Multiple export formats** (CSV, JSON, HTML reports)

- ✅ **Dark/Light mode** for comfortable analysis sessions

- ✅ **Detailed statistics** and timeline visualization

  

## 🚀 Key Features

  

### 📂 Intelligent Parsing Engine

- Automatically parses Windows Vista/7/8/10/11 Recycle Bin structures

- Extracts metadata from $I files: original filename, path, deletion timestamp, and file size

- Maps $I metadata to corresponding $R recovered file content

- Supports multi-user environments with SID-based organization

  

### 🖥️ User-Friendly Interface

- Clean, intuitive GUI built for forensic workflows

- Evidence tree view for hierarchical browsing

- List view with sortable columns

- Real-time search and filtering capabilities

- Contextual right-click menus for quick actions

  

### 📊 Comprehensive Reporting

- Export findings to CSV for spreadsheet analysis

- Generate detailed JSON reports for automation

- Create HTML reports with embedded statistics

- Timeline-based deletion analysis

- File type and size distribution statistics

  

### 🎨 Modern Design

- Dark mode for extended analysis sessions

- Light mode for documentation and presentations

- Responsive layout with customizable views

- Professional forensic tool aesthetic

  

## 📸 /Screenshots

  

### Evidence Tree View

![Evidence Tree](/Screenshots/Evidence-Tree-right-click-export.png)

*Browse through deleted items organized by user SID with comprehensive metadata display*

  

### File List View

![List View](/Screenshots/List%20view%20files.png)

*Detailed tabular view of all recovered Recycle Bin artifacts with sortable columns*

  

### Export Options

![Export Dialog](/Screenshots/Export-dialog-files.png)

*Flexible export options for CSV, JSON, and HTML report generation*

  

### Statistics Dashboard

![Statistics](/Screenshots/Statistics.png)

*Visual analytics showing deletion patterns, file types, and timeline distributions*

  

### Report Generation

![Report Export](/Screenshots/Export-report-$I-$R-csv.png)

*Professional CSV export with all forensic metadata preserved for further analysis*

  

### Context Menu Operations

![Context Menu](/Screenshots/File%20right%20click%20context%20menu.png)

*Quick access to export, copy, and analysis functions via right-click menu*

  

### File Dialog

![File Dialog](/Screenshots/File-Dialog.png)

*Easy selection of Recycle Bin sources from local or mounted forensic images*

  

### Dark Mode Interface

![Dark Mode](/Screenshots/Dark-Mode-Screenshot.png)

*Comfortable dark theme for extended forensic analysis sessions*

  

### Light Mode Interface

![Light Mode](/Screenshots/Light-Mode-Evidence-Tree-Tiles.png)

*Professional light theme with tile view for evidence presentation*

  

## 🔧 Installation

  

### Prerequisites

- Python 3.8 or higher

- Windows OS (for live analysis) or forensic image mount

- Administrative privileges (for accessing system Recycle Bin)

  

### Setup

  

```bash

# Clone the repository

git clone https://github.com/akhil-dara/RecycleBin-Forensic-Explorer.git

  

# Navigate to project directory

cd RecycleBin-Forensic-Explorer

  

# Install required dependencies

pip install -r requirements.txt

  

# Run the application

python recycle_bin_explorer.py

```

  

## 💡 Usage

  

### Quick Start

  

1. **Launch the application**

```bash

python recycle_bin_explorer.py

```

  

2. **Select Recycle Bin source**

- Click "File" → "Open Recycle Bin Location"

- Navigate to `C:\$Recycle.Bin` or mounted forensic image path

- Tool automatically parses all user SID folders

  

3. **Browse deleted items**

- Use Evidence Tree view for hierarchical navigation

- Switch to List view for detailed tabular display

- Right-click items for contextual actions

  

4. **Export findings**

- Select items or entire tree

- Right-click → "Export"

- Choose CSV, JSON, or HTML format

- Save report to case folder

  

### Advanced Features

  

#### Filtering and Search

- Use search bar to filter by filename, path, or extension

- Sort columns by clicking headers

- Filter by date range or file size

  

#### Statistics Analysis

- View "Statistics" tab for visual analytics

- Analyze deletion patterns over time

- Identify file type distributions

- Export statistics for reporting

  

#### Batch Export

- Select multiple items using Ctrl/Shift

- Export entire evidence tree with one click

- Generate comprehensive case reports

  

## 🧪 Use Cases

 

### Data Theft Investigations

Recover evidence of files deleted after unauthorized copying to external media or cloud storage.

 
### Employee Misconduct

Investigate deleted files during internal corporate investigations with user attribution via SID mapping.

## 📋 Forensic Metadata Extracted

  

| Field | Description |

|-------|-------------|

| **Original Filename** | Complete filename before deletion |

| **Original Path** | Full filesystem path where file resided |

| **Deletion Timestamp** | Exact date and time of deletion |

| **File Size** | Size in bytes of deleted file |

| **User SID** | Security Identifier of user who deleted file |

| **$I File Path** | Location of metadata file |

| **$R File Path** | Location of recoverable content file |

  

## 🔒 Forensic Soundness

  

- **Read-only analysis**: Tool never modifies source data

- **Hash verification**: Optional MD5/SHA256 verification of $R files

- **Audit logging**: All actions logged for forensic documentation

- **Chain of custody**: Preserve metadata timestamps and attributes

  


## 🤝 Contributing

  

Contributions are welcome! Whether you're fixing bugs, improving documentation, or adding new features:
  

## 📝 License

  

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

  


⭐ **Star this repository if you find it helpful for your forensic investigations!**

  

---

  

*Built with ❤️ for the Digital Forensics & Incident Response community*
