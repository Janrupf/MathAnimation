#include "core/ProjectApp.h"
#include "core/Window.h"
#include "core/GladLayer.h"
#include "core/ImGuiLayer.h"
#include "editor/ProjectScreen.h"
#include "multithreading/GlobalThreadPool.h"
#include "platform/Platform.h"

#include <imgui.h>

namespace MathAnim
{
	namespace ProjectApp
	{
		static GlobalThreadPool* globalThreadPool = nullptr;
		static Window* window = nullptr;
		static std::filesystem::path appRoot;

		static const char* winTitle = "Math Animations -- Project Selector";

		void init()
		{
			globalThreadPool = new GlobalThreadPool(std::thread::hardware_concurrency());

			// Initiaize GLFW/Glad
			window = new Window(1920, 1080, winTitle);
			window->setVSync(true);

			GladLayer::init();
			ImGuiLayer::init(*window);

			glEnable(GL_BLEND);
			glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

			std::string specialAppDirectory = Platform::getSpecialAppDir();
			g_logger_info("Special app directory: '%s'", specialAppDirectory.c_str());
			appRoot = std::filesystem::path(specialAppDirectory) / "MathAnimationEditor";
			g_logger_info("App root: '%s'", appRoot.string().c_str());
			Platform::createDirIfNotExists(appRoot.string().c_str());

			ProjectScreen::init();
		}

		std::string run()
		{
#ifdef _DEBUG
			// Automatically start the last project that was running in debug, useful for re-running the 
			// same project without having to go through the project selector
			{
				const ProjectInfo& lastSelected = ProjectScreen::getSelectedProject();
				if (!lastSelected.projectFilepath.empty() && std::filesystem::exists(lastSelected.projectFilepath))
				{
					return lastSelected.projectFilepath;
				}
			}
#endif

			// Run game loop
			// Start with a 60 fps frame rate
			bool isRunning = true;
			bool projectWasSelected = false;
			while (isRunning && !window->shouldClose())
			{
				window->pollInput();

				glViewport(0, 0, window->width, window->height);
				glClearColor(0, 0, 0, 0);

				// Do ImGui stuff
				ImGuiLayer::beginFrame();
				if (ProjectScreen::update())
				{
					window->close();
					projectWasSelected = true;
				}
				ImGuiLayer::endFrame();

				window->swapBuffers();
			}

			if (projectWasSelected)
			{
				return ProjectScreen::getSelectedProject().projectFilepath;
			}

			return "";
		}

		void free()
		{
			ProjectScreen::free();
			ImGuiLayer::free();
			Window::cleanup();
			globalThreadPool->free();
		}

		Window* getWindow()
		{
			return window;
		}

		const std::filesystem::path& getAppRoot()
		{
			return appRoot;
		}
	}
}