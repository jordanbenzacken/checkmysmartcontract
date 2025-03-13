import React from 'react';
import { Shield } from 'lucide-react';
import { CodeAnalyzer } from './components/CodeAnalyzer';

function App() {
  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600" />
              <span className="ml-2 text-xl font-semibold">SmartCheck</span>
            </div>
            <a 
              href="https://github.com/smartdec/smartcheck" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-gray-600 hover:text-blue-600 transition-colors"
            >
              View on GitHub
            </a>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Ad Space */}
        <div className="bg-gray-200 p-4 mb-8 rounded-lg text-center">
          <p className="text-gray-600">Advertisement Space</p>
        </div>

        <div className="bg-white rounded-lg shadow-md p-6">
          <div className="mb-6">
            <h1 className="text-2xl font-bold">Solidity Security Analysis</h1>
            <p className="text-gray-600 mt-2">
              Free and open-source smart contract security analyzer. Detect vulnerabilities and follow best practices.
            </p>
          </div>
          
          <CodeAnalyzer />
        </div>

        {/* Bottom Ad Space */}
        <div className="bg-gray-200 p-4 mt-8 rounded-lg text-center">
          <p className="text-gray-600">Advertisement Space</p>
        </div>
      </main>

      <footer className="bg-white mt-12 border-t">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex justify-between items-center">
            <p className="text-gray-600">
              Licensed under GPL-3.0
            </p>
            <div className="flex gap-4">
              <a 
                href="https://github.com/smartdec/smartcheck/blob/master/LICENSE" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-gray-600 hover:text-blue-600 transition-colors"
              >
                License
              </a>
              <a 
                href="https://github.com/smartdec/smartcheck" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-gray-600 hover:text-blue-600 transition-colors"
              >
                Source Code
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;