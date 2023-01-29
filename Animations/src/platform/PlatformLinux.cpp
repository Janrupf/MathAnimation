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
#include <spawn.h>

#include <openssl/evp.h>
#include <fontconfig/fontconfig.h>
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
	std::optional<std::string> findExecutable(const std::string& name) {
		auto path = std::string(getenv("PATH"));

		std::string::size_type currentSearchPos = 0;
		do {
			auto nextColon = path.find(':', currentSearchPos);
			auto entry = path.substr(currentSearchPos, nextColon);

			if (!entry.empty()) {
				auto targetExecutable = entry + "/" + name;
				if (Platform::fileExists(targetExecutable.c_str())) {
					return std::make_optional(std::move(targetExecutable));
				}
			}

			if (nextColon != std::string::npos) {
				currentSearchPos = nextColon + 1;
			} else {
				break;
			}
		} while (true);

		return std::nullopt;
	}

	struct MemMapUserData {
		int fd;
		size_t mappedSize;
	};

	namespace Platform {
		static std::vector<std::string> availableFonts;
		static bool availableFontsCached = false;
		static std::string homeDirectory = std::string();

		const std::vector<std::string> &getAvailableFonts() {
			if (!availableFontsCached) {
				FcConfig *fontConfig = FcInitLoadConfigAndFonts();

				FcPattern *pattern = FcPatternCreate();
				FcObjectSet *objectSet = FcObjectSetBuild(FC_FILE, nullptr);
				FcFontSet *fontSet = FcFontList(fontConfig, pattern, objectSet);

				g_logger_info("Found %d available fonts, caching!", fontSet->nfont);

				for (size_t i = 0; i < fontSet->nfont; i++) {
					FcPattern *font = fontSet->fonts[i];

					FcChar8 *fontFile;
					FcPatternGetString(font, FC_FILE, 0, &fontFile);

					availableFonts.emplace_back(reinterpret_cast<char *>(fontFile));
				}

				FcFontSetDestroy(fontSet);
				FcPatternDestroy(pattern);
				FcConfigDestroy(fontConfig);

				availableFontsCached = true;
			}

			return availableFonts;
		}

		// Adapted from https://stackoverflow.com/questions/2467429/c-check-installed-programms
		bool isProgramInstalled(const char *displayName) {
			auto executable = findExecutable(displayName);
			return executable.has_value();
		}

		bool getProgramInstallDir(const char *programDisplayName, char *buffer, size_t bufferLength) {
			auto maybeFoundExecutable = findExecutable(programDisplayName);
			if (!maybeFoundExecutable) {
				return false;
			}


			std::string foundExecutable = maybeFoundExecutable.value();
			std::filesystem::path p(foundExecutable);
			auto directory = std::string(p.parent_path());

			if (directory.length() > bufferLength - 1) {
				// Buffer too small
				return false;
			}

			strncpy(buffer, directory.c_str(), bufferLength);
			return true;
		}

		bool executeProgram(const char *programFilepath, const char *cmdLineArgs, const char *workingDirectory,
							const char *executionOutputFilename) {
			posix_spawnattr_t spawnAttributes;
			posix_spawnattr_init(&spawnAttributes);

			posix_spawn_file_actions_t fileActions;
			posix_spawn_file_actions_init(&fileActions);

			// We need to copy the strings because according to the POSIX standard
			// they can be modified.
			char *copiedFilePath = static_cast<char *>(g_memory_allocate(strlen(programFilepath) + 1));
			strcpy(copiedFilePath, programFilepath);

			char *copiedCmdlineArgs = static_cast<char *>(g_memory_allocate(strlen(cmdLineArgs) + 1));
			strcpy(copiedCmdlineArgs, cmdLineArgs);

			char *argv[] = { copiedFilePath, copiedCmdlineArgs, nullptr };
			int error = 0;

			if (executionOutputFilename) {
				error = posix_spawn_file_actions_addopen(
						&fileActions,
						STDOUT_FILENO,
						executionOutputFilename,
						O_WRONLY | O_TRUNC | O_CREAT,
						0644
				);

				if (error) {
					g_logger_warning("Failed queue setting the output file for execution: %s", strerror(errno));
				} else {
					error = posix_spawn_file_actions_adddup2(
							&fileActions,
							STDOUT_FILENO,
							STDERR_FILENO
					);

					if (error) {
						g_logger_warning("Failed to queue duplicating the stdout to stderr for execution: %s", strerror(errno));
					}
				}
			}

			error = posix_spawn_file_actions_addclose(&fileActions, 0);
			if (error) {
				g_logger_warning("Failed to queue closing the stdin for execution: %s", strerror(errno));
			}

			if (workingDirectory) {
				error = posix_spawn_file_actions_addchdir_np(&fileActions, workingDirectory);
				if (error) {
					g_logger_warning("Failed to queue changing the working directory for execution: %s", strerror(errno));
				}
			}

			pid_t spawnedProcessId;
			error = posix_spawn(
					&spawnedProcessId,
					programFilepath,
					&fileActions,
					&spawnAttributes,
					argv,
					environ
			);

			g_memory_free(copiedCmdlineArgs);
			g_memory_free(copiedFilePath);

			posix_spawn_file_actions_destroy(&fileActions);
			posix_spawnattr_destroy(&spawnAttributes);

			if (error) {
				g_logger_error("Failed to spawn program: %s", strerror(errno));
				return false;
			}

			g_logger_info("Spawned program %s with pid %d.", programFilepath, spawnedProcessId);

			int extendedExitStatus;
			if (waitpid(spawnedProcessId, &extendedExitStatus, 0) == -1) {
				g_logger_error("Failed to wait for child process: %s", strerror(errno));
				return false;
			}

			if (WIFSIGNALED(extendedExitStatus)) {
				int terminationSignal = WTERMSIG(extendedExitStatus);
				g_logger_warning("Child process was terminated by signal %s", terminationSignal);
			} else {
				g_logger_info("Child exited with code %d", WEXITSTATUS(extendedExitStatus));
			}

			return true;
		}

		bool openFileWithDefaultProgram(const char *filepath) {
			auto xdgOpen = findExecutable("xdg-open");
			if (!xdgOpen) {
				g_logger_warning("Unable to open %s, xdg-open was not found!", filepath);
				return false;
			}

			return executeProgram(xdgOpen->c_str(), filepath);
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