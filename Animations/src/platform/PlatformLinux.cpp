#ifdef __linux

#include "platform/Platform.h"
#include "core.h"

#include <filesystem>

extern "C" {
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pwd.h>
#include <fcntl.h>

#include <openssl/evp.h>
}

#ifdef min
#undef min
#endif

/* Make a directory; already existing dir okay */
static int maybe_mkdir(const char *path, mode_t mode) {
	struct stat st;
	errno = 0;

	/* Try to make the directory */
	if (mkdir(path, mode) == 0)
		return 0;

	/* If it fails for any reason but EEXIST, fail */
	if (errno != EEXIST)
		return -1;

	/* Check if the existing path is a directory */
	if (stat(path, &st) != 0)
		return -1;

	/* If not, fail with ENOTDIR */
	if (!S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		return -1;
	}

	errno = 0;
	return 0;
}

static int mkdir_p(const char *path, mode_t mode) {
	/* Adapted from http://stackoverflow.com/a/2336245/119527 */
	char *_path = NULL;
	char *p;
	int result = -1;

	errno = 0;

	/* Copy string so it's mutable */
	_path = strdup(path);
	if (_path == NULL)
		goto out;

	/* Iterate the string */
	for (p = _path + 1; *p; p++) {
		if (*p == '/') {
			/* Temporarily truncate */
			*p = '\0';

			if (maybe_mkdir(_path, mode) != 0)
				goto out;

			*p = '/';
		}
	}

	if (maybe_mkdir(_path, mode) != 0)
		goto out;

	result = 0;

	out:
	free(_path);
	return result;
}

namespace MathAnim {
	struct MemMapUserData {
		int fd;
		size_t mappedSize;
	};

	namespace Platform {
		static std::vector<std::string> availableFonts = {
				"JetBrains Mono"};
		static bool availableFontsCached = false;
		static std::string homeDirectory = std::string();

		const std::vector<std::string> &getAvailableFonts() {
			if (!availableFontsCached) {
				// TODO: Placeholder cuz it's 01:39
				availableFontsCached = true;
			}

			return availableFonts;
		}

		// Adapted from https://stackoverflow.com/questions/2467429/c-check-installed-programms
		bool isProgramInstalled(const char *displayName) {
			g_logger_warning("UNIMPLEMENTED: Failing check if %s is installed", displayName);
			// TODO: Placeholder, but also this function seems unused?
			return false;
		}

		bool getProgramInstallDir(const char *programDisplayName, char *buffer, size_t bufferLength) {
			// TODO: I'm used to Rust or managed languages and string handling in C/++ scares me

			std::string const path = std::getenv("PATH");
			char const delim = ':';

			auto start = 0U;
			auto end = path.find(delim);
			while (true) {
				auto const folder = path.substr(start, end - start);

				int i = 1;

				for (auto const &directory_entry: std::filesystem::directory_iterator(folder)) {
					auto const file = directory_entry.path();
					if (strcmp(file.filename().c_str(), programDisplayName) == 0 && access(file.c_str(), X_OK) == 0) {
						strncpy(buffer, file.parent_path().c_str(), bufferLength - 1);
						// Append / to the end of the path
						buffer[strlen(buffer) + 1] = '\0';
						buffer[strlen(buffer)] = '/';
						return true;
					}
				}
				if (end == std::string::npos) {
					break;
				}
				start = end + 1;
				end = path.find(delim, start);
			}

			return false;
		}

		bool executeProgram(const char *programFilepath, const char *cmdLineArgs, const char *workingDirectory,
							const char *executionOutputFilename) {
			g_logger_warning("UNIMPLEMENTED: Trying to execute another program");
			return false;
		}

		bool openFileWithDefaultProgram(const char *filepath) {
			return executeProgram("code", filepath);
		}

		bool openFileWithVsCode(const char *filepath, int lineNumber) {
			std::string arg = lineNumber >= 0
							  ? std::string("--goto \"") + filepath + ":" + std::to_string(lineNumber) + "\""
							  : std::string("--goto \"") + filepath + "\"";
			executeProgram("code", arg.c_str());
		}

		bool fileExists(const char *filename) {
			struct stat file_stat;
			return (stat(filename, &file_stat) == 0) && S_ISREG(file_stat.st_mode);
		}

		bool dirExists(const char *dirName) {
			struct stat file_stat;
			return (stat(dirName, &file_stat) == 0) && S_ISDIR(file_stat.st_mode);
		}

		bool deleteFile(const char *filename) {
			return std::remove(filename) == 0;
		}

		std::string getSpecialAppDir() {
			if (homeDirectory.empty()) {
				const char *homeVar = getenv("HOME");
				if (homeVar == nullptr) {
					homeDirectory = std::string(getpwuid(getuid())->pw_dir);
				} else {
					homeDirectory = std::string(homeVar);
				}
			}

			return homeDirectory + "/.mathanimation";
		}

		MemMappedFile *createTmpMemMappedFile(const std::string &directory, size_t size) {
			int temporaryFd = ::open(directory.c_str(), O_TMPFILE | O_RDWR | O_CLOEXEC | O_EXCL | S_IRUSR | S_IWUSR);
			if (temporaryFd == -1) {
				g_logger_error("Failed to create temporary file in '%s': %s", directory.c_str(), strerror(errno));
				return nullptr;
			}

			if (::ftruncate64(temporaryFd, (off64_t) size) == -1) {
				g_logger_error("Failed to resize temporary file: %s", strerror(errno));
				::close(temporaryFd);
				return nullptr;
			}

			int pageSize = ::getpagesize();

			size_t mappedSize = size;
			size_t misalignment = mappedSize % pageSize;

			// We need to round up to a multiple of page size so that we can
			// memory map the file.
			if (misalignment != 0) {
				mappedSize += pageSize - misalignment;
			}

			void *mappingResult = ::mmap(
					nullptr,
					mappedSize,
					PROT_READ | PROT_WRITE,
					MAP_SHARED | MAP_NORESERVE,
					temporaryFd,
					0
			);

			if (mappingResult == MAP_FAILED) {
				g_logger_error("Failed to map file to memory: %s", strerror(errno));
				::close(temporaryFd);
				return nullptr;
			}

			auto *file = static_cast<MemMappedFile *>(g_memory_allocate(sizeof(MemMappedFile)));
			// Gross hack, field is marked const, but we need to assign it
			*const_cast<uint8**>(&file->data) = static_cast<uint8*>(mappingResult);
			file->dataSize = size;

			auto *data = static_cast<MemMapUserData *>(g_memory_allocate(sizeof(MemMapUserData)));
			data->fd = temporaryFd;

			// This is the real size of the mapping.
			//
			// The size of the file may be smaller, but since we always need
			// to map multiple's of the page size, we need to store this
			// separately.
			data->mappedSize = mappedSize;

			file->userData = data;

			return file;
		}

		void freeMemMappedFile(MemMappedFile* file) {
			if (!file) {
				return;
			}

			auto* userData = static_cast<MemMapUserData *>(file->userData);
			int unmapResult = ::munmap(file->data, userData->mappedSize);

			if (unmapResult == -1) {
				g_logger_error("Failed to unmap file: %s", strerror(errno));
			}

			if (::close(userData->fd) == -1) {
				g_logger_error("Failed to close memory mapped file: %s", strerror(errno));
			}

			g_memory_free(userData);
			g_memory_free(file);
		}

		void createDirIfNotExists(const char *dirName) {
			mkdir_p(dirName, 0755);
		}

		std::string md5FromString(const std::string &str, int md5Length) {
			return md5FromString(str.c_str(), str.length(), md5Length);
		}

		std::string md5FromString(char const *const str, size_t length, int md5Length) {
			unsigned int md5_digest_len = EVP_MD_size(EVP_md5());
			g_logger_assert(length == md5_digest_len, "Cannot generate md5 of size %d. Must be %d", md5Length,
							md5_digest_len);

			// MD5_Init
			EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
			EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

			// MD5_Update
			EVP_DigestUpdate(mdctx, str, length);

			// MD5_Final
			unsigned char *md5_digest = (unsigned char *) OPENSSL_malloc(md5_digest_len);
			EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
			EVP_MD_CTX_free(mdctx);
			// TODO: Is this how strings work? I dunno
			return std::string((char *) md5_digest);
		}
	}
}

#endif